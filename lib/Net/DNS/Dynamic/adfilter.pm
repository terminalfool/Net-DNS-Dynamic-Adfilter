package Net::DNS::Dynamic::Adfilter;

our $VERSION = '0.062';

use Moose;
use LWP::Simple;
use IO::Socket::INET;

extends 'Net::DNS::Dynamic::Proxyserver';

has adfilter=> ( is => 'rw', isa => 'HashRef', required => 0 );
has ask_pgl_hosts=> ( is => 'rw', isa => 'HashRef', required => 0 );
has ask_more_hosts=> ( is => 'rw', isa => 'HashRef', required => 0 );

override 'run' => sub {

	my ( $self ) = shift;

	my $sock = IO::Socket::INET->new(
		PeerAddr=> "example.com",
		PeerPort=> 80,
		Proto   => "tcp");
	my $localip = $sock->sockhost;

#--switch dns settings on mac osx, wireless interface
#	system("networksetup -setdnsservers \"Wi-Fi\" $localip");
#	system("networksetup -setsearchdomains \"Wi-Fi\" localhost");
#--

	$self->log("Nameserver accessible locally @ $localip", 1);

	$self->nameserver->main_loop;
};

#--restore dns settings on mac osx, wireless interface
#before 'signal_handler' => sub {
#	my ( $self ) = shift;
#	system('networksetup -setdnsservers "Wi-Fi" empty');
#	system('networksetup -setsearchdomains "Wi-Fi" empty');
#};
#--

around 'reply_handler' => sub {
        my $orig = shift;
        my $self = shift;
        my ($qname, $qclass, $qtype, $peerhost, $query, $conn) = @_;

        my ($rcode, @ans, @auth, @add);

 	# see if we can answer the question from hosts listings
 	#
 	if ($self->adfilter && ($qtype eq 'A' || $qtype eq 'PTR')) {
    
 		if (my $ip = $self->query_adfilter( $qname, $qtype )) {

                 	$self->log("received query from $peerhost: qtype '$qtype', qname '$qname'");
 			$self->log("[local host listings] resolved $qname to $ip NOERROR");

                        my $refresh = $self->ask_pgl_hosts->{adhosts_refresh} || 7;

 			my ($ttl, $rdata) = ((int(abs($refresh)) * 86400), $ip );
        
 			push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");

 			$rcode = "NOERROR";
      
 			return ($rcode, \@ans, \@auth, \@add, { aa => 1, ra => 1 });
 		}
 	}
	return $self->$orig(@_);
};

after 'read_config' => sub {
 	my ( $self ) = shift;
        my $cache = ();

 	if ($self->ask_pgl_hosts) {
 	        $cache = { $self->parse_pgl_hosts() };  # pgl.yoyo.org hosts
    	        %{ $self->{adfilter} } = %{ $cache };
 	}
        if ($self->ask_more_hosts) {
 	        $cache = { $self->parse_more_hosts() }; # local, custom hosts
                %{ $self->{adfilter} } = $self->adfilter ? ( %{ $self->{adfilter} }, %{ $cache } ) 
                                         : %{ $cache };
 	}
 	return;
};

sub query_adfilter {
	my ( $self, $qname, $qtype ) = @_;

	$qname =~ s/^.*\.(\w+\.\w+)$/$1/ if $qtype eq 'A';
	
	return $self->search_ip_in_adfilter( $qname ) if $qtype eq 'A';
	return $self->search_hostname_by_ip( $qname ) if $qtype eq 'PTR';
}

sub search_ip_in_adfilter {
        my ( $self, $hostname ) = @_;

        return '::1' if (exists $self->adfilter->{$hostname});
        return;
}

sub parse_pgl_hosts {
	my ( $self ) = shift;

	return unless $self->ask_pgl_hosts;

	my %cache;

	my $hostsfile = $self->ask_pgl_hosts->{path} or die "ask_pgl_hosts->{path} is undefined";
	my $refresh = $self->ask_pgl_hosts->{refresh} || 7;
	my $age = -M $hostsfile || $refresh;

	if ($age >= $refresh) {
        	my $url = $self->ask_pgl_hosts->{url} or die "attempting to refresh $hostsfile failed as ask_pgl_hosts->{url} is undefined";
	        $self->log("refreshing pgl hosts: $hostsfile", 1);
	        getstore($url, $hostsfile);
	}

	%cache = $self->parse_single_col_hosts($hostsfile);
		
	return %cache;
}

sub parse_more_hosts {
	my ( $self ) = shift;

	return unless my $hostsfile = $self->ask_more_hosts->{path};

	my %cache;

	%cache = $self->parse_single_col_hosts($hostsfile);
		
	return %cache;
}

sub parse_single_col_hosts {
	my ( $self, $hostsfile ) = @_;

	my %hosts;

	open(HOSTS, $hostsfile) or die "cant open $hostsfile file: $!";

	while (<HOSTS>) {
	        chomp;
		next if /^\s*#/; # skip comments
		next if /^$/;    # skip empty lines
		s/\s*#.*$//;     # delete in-line comments and preceding whitespace
		$hosts{$_}++;
	}

	close(HOSTS);

	return %hosts;
}

__PACKAGE__->meta->make_immutable;

1;

=head1 NAME

Net::DNS::Dynamic::Adfilter - A DNS ad filter

=head1 DESCRIPTION

This is a DNS server intended for use as an ad filter for a local area network. 
Its function is to load lists of ad domains and nullify DNS queries for those 
domains to the loopback address. Any other DNS queries are proxied upstream, 
either to a specified list of nameservers or to those listed in /etc/resolv.conf. 
The module can also load and resolve host definitions found in /etc/hosts as 
well as hosts defined in a sql database.

Externally maintained lists of ad hosts may be loaded periodically through a specified 
url. A local addendum of hosts may also be specified. Ad host listings must conform 
to a one host per line format:

  # ad nauseam
  googlesyndication.com
  facebook.com
  twitter.com
  ...
  adinfinitum.com

Once running, local network dns queries can be addressed to the host's ip. This ip is 
echoed to stdout.

=head1 SYNOPSIS

    my $adfilter = Net::DNS::Dynamic::Adfilter->new();

    $adfilter->run();

Without any arguments, the module will function simply as a proxy, forwarding all requests 
upstream to nameservers defined in /etc/resolv.conf.

=head1 ATTRIBUTES

=head2 ask_pgl_hosts

    my $adfilter = Net::DNS::Dynamic::Adfilter->new(

        ask_pgl_hosts => {
            url => 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&&mimetype=plaintext',
            path => '/var/named/adhosts',     #path to ad hosts
            refresh => 7,                     #ttl in days (default = 7)
        },
    );

The ask_pgl_hosts hashref defines a url that returns a single column list of ad hosts. In the 
module's current version, this is the only acceptable format. A path string defines where the 
module will write a local copy of this list. The refresh value determines what age (in days) 
the local copy may be before it is refreshed. This value also determines the lifespan (ttl) 
of queries based upon this list.

=head2 ask_more_hosts

    my $adfilter = Net::DNS::Dynamic::Adfilter->new(

        ask_more_hosts => {
            path => '/var/named/morehosts',  #path to secondary hosts
        },
    );

The ask_more_hosts hashref contains only a path string that defines where the module will access an 
addendum of ad hosts to nullify. As above, a single column is the only acceptable format.

=head1 LEGACY ATTRIBUTES

From the parent class Net::DNS::Dynamic::Proxyserver.

=head2 ask_etc_hosts

    my $adfilter = Net::DNS::Dynamic::Adfilter->new(

        ask_etc_hosts => { ttl => 3600 },	 #if set, parse and resolve /etc/hosts; ttl in seconds
    );

Definition of ask_etc_hosts activates parsing of /etc/hosts and resolution of matching queries 
with a lifespan of ttl (in seconds).

=head2 ask_sql_hosts

If defined, the module will query an sql database of hosts, provided the database file can be 
accessed (read/write) with the defined uid/gid.

    my $adfilter = Net::DNS::Dynamic::Adfilter->new( 

        ask_sql => {
  	    ttl => 60, 
	    dsn => 'DBI:mysql:database=db_name;host=localhost;port=3306',
	    user => 'my_user',
	    pass => 'my_password',
	    statement => "SELECT ip FROM hosts WHERE hostname='{qname}' AND type='{qtype}'"
        },
        uid => 65534, #only if necessary
        gid => 65534,
    );

The 'statement' is a SELECT statement, which must return the IP address for the given query name 
(qname) and query type (qtype, like 'A' or 'MX'). The placeholders {qname} and {qtype} will be 
replaced by the actual query name and type. Your statement must return the IP address as the 
first column in the result.

=head2 debug

The debug option logs actions to stdout and may be set from 1-3 with increasing 
output: the module will feedback (1) adfilter.pm logging, (2) nameserver logging, 
and (3) resolver logging. 

=head2 host

The IP address to bind to. If not defined, the server binds to all (*).

=head2 port

The tcp & udp port to run the DNS server under. Defaults to 53.

=head2 uid

The optional user id to switch to after the socket has been created.

=head2 gid

The optional group id to switch to after the socket has been created.

=head2 nameservers

An arrayref of one or more nameservers to forward any DNS queries to. Defaults to nameservers 
listed in /etc/resolv.conf.

=head2 nameservers_port

Specify the port of the remote nameservers. Defaults to the standard port 53.

=head1 CAVEATS

It will be necessary to manually adjust the host's network dns settings to take advantage 
of the filtering. On Mac hosts, uncommenting the I<networksetup> system calls of adfilter.pm will 
automate this.

=head1 AUTHOR

David Watson <dwatson@cpan.org>

=head1 SEE ALSO

scripts/adfilter.pl in the distribution

Net::DNS::Dynamic::Proxyserver

=head1 COPYRIGHT AND LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

The full text of the license can be found in the LICENSE file included with this module.

=cut
