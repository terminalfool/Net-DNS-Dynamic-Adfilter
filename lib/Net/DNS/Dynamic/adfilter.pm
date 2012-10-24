package Net::DNS::Dynamic::Adfilter;

our $VERSION = '0.069';

use Moose;
use Sys::HostIP;
use Capture::Tiny qw(capture);
use LWP::Simple qw($ua getstore);
$ua->agent("");

#use Data::Dumper;

extends 'Net::DNS::Dynamic::Proxyserver';

has adblock_stack => ( is => 'rw', isa => 'ArrayRef', required => 0 );
has blacklist => ( is => 'rw', isa => 'HashRef', required => 0 );
has whitelist => ( is => 'rw', isa => 'HashRef', required => 0 );
has adfilter => ( is => 'rw', isa => 'HashRef', required => 0 );
has host => ( is => 'rw', isa => 'Str', required => 0, default => sub { Sys::HostIP->ip } );
has network => ( is => 'rw', isa => 'HashRef', required => 0 );
has setdns => ( is => 'rw', isa => 'Int', required => 0, default => 0 );

override 'run' => sub {
	my ( $self ) = shift;

	if ( $self->setdns ) {
	        my $host = Sys::HostIP->new;
	        my %devices = reverse %{ $host->interfaces };
                $self->{network}->{interface} = $devices{ $self->host };

                $self->set_local_dns;
	}

	$self->nameserver->main_loop;
};

before 'signal_handler' => sub {
	my ( $self ) = shift;

        $self->restore_local_dns if $self->setdns;
};

around 'reply_handler' => sub {                         # query ad listings
        my $orig = shift;
        my $self = shift;
        my ($qname, $qclass, $qtype, $peerhost, $query, $conn) = @_;

        my ($rcode, @ans, @auth, @add);

 	if ($self->adfilter && ($qtype eq 'AAAA' || $qtype eq 'A' || $qtype eq 'PTR')) {
    
 		if (my $ip = $self->query_adfilter( $qname, $qtype )) {

                 	$self->log("received query from $peerhost: qtype '$qtype', qname '$qname'");
 			$self->log("[local host listings] resolved $qname to $ip NOERROR");

 			my ($ttl, $rdata) = ( 300, $ip );
        
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

        if ($self->adblock_stack) {
        	for ( @{ $self->adblock_stack } ) {
 	                $cache = { $self->load_adblock_filter($_) };                  # adblock plus hosts
                        %{ $self->{adfilter} } = $self->adfilter ? ( %{ $self->{adfilter} }, %{ $cache } ) 
                                         : %{ $cache };
	        }
	}
        if ($self->blacklist) {
 	        $cache = { $self->parse_single_col_hosts($self->blacklist->{path}) }; # local, custom hosts
                %{ $self->{adfilter} } = $self->adfilter ? ( %{ $self->{adfilter} }, %{ $cache } ) 
                                         : %{ $cache };
 	}
        if ($self->whitelist) {
 	        $cache = { $self->parse_single_col_hosts($self->whitelist->{path}) }; # remove entries
                for ( keys %{ $cache } ) { delete ( $self->{adfilter}->{$_} ) };
 	}

#	$self->dump_adfilter;

 	return;
};

sub query_adfilter {
	my ( $self, $qname, $qtype ) = @_;

	return $self->search_ip_in_adfilter( $qname ) if  ($qtype eq 'A' || $qtype eq 'AAAA');
	return $self->search_hostname_by_ip( $qname ) if $qtype eq 'PTR';
}

sub search_ip_in_adfilter {
        my ( $self, $hostname ) = @_;

	my $trim = $hostname;
	my $sld = $hostname;
	$trim =~ s/^www\.//i;
	$sld =~ s/^.*\.(\w+\.\w+)$/$1/;

	return '::1' if ( exists $self->adfilter->{$hostname} ||
			  exists $self->adfilter->{$trim} ||
			  exists $self->adfilter->{$sld} );
        return;
}

sub load_adblock_filter {
	my ( $self ) = shift;
	my %cache;

	my $hostsfile = $_->{path} or die "adblock {path} is undefined";
	my $refresh = $_->{refresh} || 7;
	my $age = -M $hostsfile || $refresh;

	if ($age >= $refresh) {
        	my $url = $_->{url} or die "attempting to refresh $hostsfile failed as {url} is undefined";
	        $url =~ s/^\s*abp:subscribe\?location=//;
                $url =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
                $url =~ s/&.*$//;
	        $self->log("refreshing hosts: $hostsfile", 1);
	        getstore($url, $hostsfile);
	}

	%cache = $self->parse_adblock_hosts($hostsfile);
		
	return %cache;
}

sub parse_adblock_hosts {
	my ( $self, $hostsfile ) = @_;
	my %hosts;

	open(HOSTS, $hostsfile) or die "cant open $hostsfile file: $!";

	while (<HOSTS>) {
	        chomp;
		next unless s/^\|\|((\w+\.)+\w+)\^(\$third-party)?$/$1/;  #extract adblock host
		$hosts{$_}++;
	}

	close(HOSTS);

	return %hosts;
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

sub set_local_dns {
	my ( $self ) = shift;

	my $stdout;
	my $stderr;
	my @result;

        if ($^O	=~ /darwin/i) {                                                          # is osx
	        eval {
	                ($self->{network}->{service}, $stderr, @result) = capture { system("networksetup -listallhardwareports | grep -B 1 $self->{network}->{interface} | cut -c 16-32") };
			if ($stderr || ($result[0] < 0)) {
			       die $stderr || $result[0];
			} else {
			       $self->{network}->{service} =~ s/\n//g;
			       system("networksetup -setdnsservers $self->{network}->{service} $self->{host}");
			       system("networksetup -setsearchdomains $self->{network}->{service} empty");
			}
		}
	}

	if (!grep { $^O eq $_ } qw(VMS MSWin32 os2 dos MacOS darwin NetWare beos vos)) { # is unix
	        eval {
	                ($stdout, $stderr, @result) = capture { system("cp /etc/resolv.conf /etc/resolv.bk") };
			if ($stderr || ($result[0] < 0)) {
			       die $stderr || $result[0];
			} else {
			       open(CONF, ">", "/etc/resolv.conf");
			       print CONF "nameserver $self->{host}\n";
			       close CONF;
			}
                }
	}

	if ($stderr||$result[0]) {
	       $self->log("switching of local dns settings failed: $@", 1);
	       undef $self->setdns;
	} else {
	       $self->log("local dns settings ($self->{network}->{interface}) switched", 1);
	}
}

sub restore_local_dns {
	my ( $self ) = shift;

	my $stdout;
	my $stderr;
	my @result;

        if ($^O	=~ /darwin/i) {                                                         # is osx
	        eval {
		        ($stdout, $stderr, @result) = capture { system("networksetup -setdnsservers $self->{network}->{service} empty") };
			if ($stderr || ($result[0] < 0)) {
			       die $stderr || $result[0];
			} else {
                               system("networksetup -setsearchdomains $self->{network}->{service} empty");
			}
                }
	}

	if (!grep { $^O eq $_ } qw(VMS MSWin32 os2 dos MacOS darwin NetWare beos vos)) { # is unix
	        eval {
                        ($stdout, $stderr, @result) = capture { system("mv /etc/resolv.bk /etc/resolv.conf") };
			die $stderr || $result[0];
                }
        }

	($stderr||$result[0]) ? $self->log("local dns settings failed to restore: $@", 1)
	        : $self->log("local dns settings restored", 1);
}

sub dump_adfilter {
	my $self = shift;

	my $str = Dumper(\%{ $self->adfilter });
	open(OUT, ">/var/named/adfilter_dumpfile") or die "cant open dump file: $!";
	print OUT $str;
	close OUT;
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

The module loads externally maintained lists of ad hosts intended for use by 
Adblock Plus, a popular ad filtering extension for the Firefox browser. Use 
of the lists focuses only on third-party listings that define dedicated 
advertising and tracking hosts.

A locally maintained blacklist/whitelist can also be loaded. In this case, host 
listings must conform to a one host per line format.

Once running, local network dns queries can be addressed to the host's ip. This 
ip is echoed to stdout.

=head1 SYNOPSIS

    my $adfilter = Net::DNS::Dynamic::Adfilter->new();

    $adfilter->run();

Without any arguments, the module will function simply as a proxy, forwarding all 
requests upstream to nameservers defined in /etc/resolv.conf.

=head1 ATTRIBUTES

=head2 adblock_stack

    my $adfilter = Net::DNS::Dynamic::Adfilter->new(

        adblock_stack => [
            {
            url => 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&startdate[day]=&startdate[month]=&startdate[year]=&mimetype=plaintext',
	    path => '/var/named/pgl-adblock.txt',     #path to ad hosts
            refresh => 7,                             #refresh value in days (default = 7)
            },

            {
            url => 'abp:subscribe?location=https%3A%2F%2Feasylist-downloads.adblockplus.org%2Feasyprivacy.txt&title=EasyPrivacy&requiresLocation=https%3A%2F%2Feasylist-downloads.adblockplus.org%2Feasylist.txt&requiresTitle=EasyList';
            path => '/var/named/easyprivacy.txt',
            refresh => 5,
            },
        ],
    );

The adblock_stack arrayref encloses one or more hashrefs composed of three 
parameters: a url that returns a list of ad hosts in adblock plus format; 
a path string that defines where the module will write a local copy of 
the list; a refresh value that determines what age (in days) the local copy 
may be before it is refreshed.

There are dozens of adblock plus filters scattered throughout the internet. 
You can load as many as you like, though one or two lists such as those listed 
above should suffice.

A collection of lists is available at http://adblockplus.org/en/subscriptions. 
The module will accept standard or abp:subscribe? urls. You can cut and paste 
encoded links directly.

=head2 blacklist

    my $adfilter = Net::DNS::Dynamic::Adfilter->new(

        blacklist => {
            path => '/var/named/blacklist',  #path to secondary hosts
        },
    );

The blacklist hashref contains only a path string that defines where the module will 
access a local list of ad hosts to nullify. As mentioned above, a single column is the 
only acceptable format:

    # ad nauseam
    googlesyndication.com
    facebook.com
    twitter.com
    ...
    adinfinitum.com

=head2 whitelist

    my $adfilter = Net::DNS::Dynamic::Adfilter->new(

        whitelist => {
            path => '/var/named/whitelist',  #path to whitelist
        },
    );

The whitelist hashref, like the blacklist hashref, contains only a path parameter 
to a single column list of hosts. These hosts will be removed from the filter.

=head2 host, port

    my $adfilter = Net::DNS::Dynamic::Adfilter->new( host => $host, port => $port );

The IP address to bind to. If not defined, the server attempts binding to the local ip.
The default port is 53.

=head2 nameservers, nameservers_port

    my $adfilter = Net::DNS::Dynamic::Adfilter->new( nameservers => [ $ns1, $ns2, ], nameservers_port => $port );

An arrayref of one or more nameservers to forward any DNS queries to. Defaults to nameservers 
listed in /etc/resolv.conf. The default port is 53.

=head2 setdns

    my $adfilter = Net::DNS::Dynamic::Adfilter->new( setdns  => '1' } ); #defaults to '0'

If set, the module attempts to set local dns settings to the host's ip. This may or may not work
if there are multiple active interfaces. You may need to manually adjust your local dns settings.

=head2 debug

    my $adfilter = Net::DNS::Dynamic::Adfilter->new( debug => '1' ); #defaults to '0'

The debug option logs actions to stdout and can be set from 1-3 with increasing 
output: the module will feedback (1) adfilter.pm logging, (2) nameserver logging, 
and (3) resolver logging. 

=head2 ask_etc_hosts

    my $adfilter = Net::DNS::Dynamic::Adfilter->new(

        ask_etc_hosts => { ttl => 3600 },	 #if set, parse and resolve /etc/hosts; ttl in seconds
    );

Definition of ask_etc_hosts activates parsing of /etc/hosts and resolution of matching queries 
with a lifespan of ttl (in seconds). See Net::DNS::Dynamic::Proxyserver for more info.

=head2 ask_sql_hosts

If defined, the module will query an sql database of hosts, provided the database file can be 
accessed (read/write) with the defined uid/gid. See Net::DNS::Dynamic::Proxyserver for more info.

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

=head2 uid

The optional user id to switch to after the socket has been created.

=head2 gid

The optional group id to switch to after the socket has been created.

=head1 CAVEATS

Written and tested under darwin only.

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
