package Net::DNS::Dynamic::Adfilter;

our $VERSION = '0.05';

use Moose;
use LWP::Simple;
use IO::Socket::INET;
use Carp qw( croak );

extends 'Net::DNS::Dynamic::Proxyserver';

has cache=> ( is => 'rw', isa => 'HashRef', required => 0 );
has ask_adhosts=> ( is => 'rw', isa => 'HashRef', required => 0 );
has ask_morehosts=> ( is => 'rw', isa => 'HashRef', required => 0 );

override 'run' => sub {

	my ( $self ) = shift;

	my $sock = IO::Socket::INET->new(
		PeerAddr=> "example.com",
		PeerPort=> 80,
		Proto   => "tcp");
	my $localip = $sock->sockhost;

#--switch dns settings on mac osx, wireless interface
	system("networksetup -setdnsservers \"Wi-Fi\" $localip");
	system("networksetup -setsearchdomains \"Wi-Fi\" localhost");
#--

	$self->log("Nameserver accessible locally @ $localip", 1);

	$self->nameserver->main_loop;
};

#--restore dns settings on mac osx, wireless interface
before 'signal_handler' => sub {
	my ( $self ) = shift;
	system('networksetup -setdnsservers "Wi-Fi" empty');
	system('networksetup -setsearchdomains "Wi-Fi" empty');
};
#--

override 'reply_handler' => sub {

	my ($self, $qname, $qclass, $qtype, $peerhost, $query, $conn) = @_;

	my ($rcode, @ans, @auth, @add);

	$self->log("received query from $peerhost: qtype '$qtype', qname '$qname'");

	# see if we can answer the question from /etc/hosts
	#
	if ($self->ask_etc_hosts && ($qtype eq 'A' || $qtype eq 'PTR')) {
	
		if (my $ip = $self->query_etc_hosts( $qname, $qtype )) {

			$self->log("[/etc/hosts] resolved $qname to $ip NOERROR");

			my ($ttl, $rdata) = (($self->ask_etc_hosts->{ttl} ? $self->ask_etc_hosts->{ttl} : 3600), $ip );
        
			push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");

			$rcode = "NOERROR";
			
			return ($rcode, \@ans, \@auth, \@add, { aa => 1, ra => 1 });
		}
	}

	# see if we can answer the question from hosts listings
	#
	if ($self->cache && ($qtype eq 'A' || $qtype eq 'PTR')) {
    
		if (my $ip = $self->query_cache( $qname, $qtype )) {

			$self->log("[local host listings] resolved $qname to $ip NOERROR");

                        my $refresh = $self->ask_adhosts->{adhosts_refresh} || 7;

			my ($ttl, $rdata) = ((int(abs($refresh)) * 86400), $ip );
        
			push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");

			$rcode = "NOERROR";
      
			return ($rcode, \@ans, \@auth, \@add, { aa => 1, ra => 1 });
		}
	}

	# see if we can answer the question from the SQL database
	#
	if ($self->ask_sql) {
    
		if (my $ip = $self->query_sql( $qname, $qtype )) {
      
			$self->log("[SQL] resolved $qname to $ip NOERROR");

			my ($ttl, $rdata) = (($self->ask_sql->{ttl} ? $self->ask_sql->{ttl} : 3600), $ip );
        
			push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");

			$rcode = "NOERROR";
      
			return ($rcode, \@ans, \@auth, \@add, { aa => 1, ra => 1 });
		}
    }

	# forward to remote nameserver and loop through the result
	# 
	my $answer = $self->resolver->send($qname, $qtype, $qclass);

	if ($answer) {

		$rcode = $answer->header->rcode;
		@ans   = $answer->answer;
		@auth  = $answer->authority;
		@add   = $answer->additional;
    
		$self->log("[proxy] response from remote resolver: $qname $rcode");

		return ($rcode, \@ans, \@auth, \@add);
	}
	else {

		$self->log("[proxy] can not resolve $qtype $qname - no answer from remote resolver. Sending NXDOMAIN response.");

		$rcode = "NXDOMAIN";

		return ($rcode, \@ans, \@auth, \@add, { aa => 1, ra => 1 });
	}
};

after 'read_config' => sub {
	my ( $self ) = shift;

	return unless $self->ask_adhosts;

	$self->ask_adhosts->{cache} = { $self->parse_pgl_hosts() }; # pgl.yoyo.org hosts
	$self->ask_morehosts->{cache} = { $self->parse_more_hosts() }; # local, custom hosts
	%{ $self->{cache} } = ( %{ $self->ask_adhosts->{cache} }, %{ $self->ask_morehosts->{cache} } );
};

sub query_cache {
	my ( $self, $qname, $qtype ) = @_;

	$qname =~ s/^.*\.(\w+\.\w+)$/$1/i;
	
	return $self->search_ip_in_cache( $qname ) if $qtype eq 'A';
	return $self->search_hostname_by_ip( $qname ) if $qtype eq 'PTR';
}

sub search_ip_in_cache {
        my ( $self, $hostname ) = @_;

        return '::1' if (exists $self->cache->{$hostname});
#        return '127.0.0.1' if (exists $self->cache->{$hostname});
        return;
}

sub parse_pgl_hosts {
	my ( $self ) = shift;

	return unless $self->ask_adhosts->{refresh};

	my %cache;

	my $hostsfile = $self->ask_adhosts->{path};
	my $age = -M $hostsfile || 0;

	if ($age > $self->ask_adhosts->{refresh}) {
	        $self->log("refreshing pgl hosts: $hostsfile", 1);
	        getstore($self->ask_adhosts->{url}, $hostsfile);
	}

	%cache = $self->parse_single_col_hosts($hostsfile) if -e $hostsfile;
		
	return %cache;
}

sub parse_more_hosts {
	my ( $self ) = shift;

	return unless $self->ask_morehosts->{path};

	my %cache;

	my $hostsfile = $self->ask_morehosts->{path};

	%cache = $self->parse_single_col_hosts($hostsfile) if -e $hostsfile;
		
	return %cache;
}

sub parse_single_col_hosts {
	my ( $self, $hostsfile ) = @_;

	my %hosts;

	open(HOSTS, $hostsfile) or croak "cant open $hostsfile file: $!";

	while (<HOSTS>) {
	        chomp;
		next if /^\s*#/;# skip comments
		next if /^$/; # skip empty lines
		s/\s*#.*$//;# delete in-line comments and preceding whitespace
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

This is a Perl DNS server intended for use as an ad filter for a local area network. 
The module loads a list of ad domains and resolves DNS queries for those domains to 
the loopback address 127.0.0.1. The module forwards any other requests downstream 
to a specified list of nameservers or determines forwarding according to /etc/resolv.conf. 
The module can also load and resolve any /etc/hosts definitions that might exist. 

A dynamic list of ad domains (adhosts) is accessed through a supplied url. An addendum 
of ad domains (morehosts) may also be specified. Ad host listings must conform to a 
one host per line format:

  # ad nauseam
  googlesyndication.com
  facebook.com
  twitter.com
  ...
  adinfinitum.com

Once running, local network dns queries can be addressed to the host's ip. This ip is 
echoed to stdout.

=head1 SYNOPSIS

my $adfilter = Net::DNS::Dynamic::Adfilter->new(

     ask_adhosts => {
                     refresh => 7,                     #ttl in days
                     url => 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&&mimetype=plaintext',
                     path => '/var/named/adhosts',     #path to ad hosts
                    },
     ask_morehosts => {
                     path => '/var/named/morehosts',   #path to secondary hosts
                    },
     ask_etc_hosts => { ttl => 3600 },	                   #if set, parse and resolve /etc/hosts as well; ttl in seconds
     );

$adfilter->run();

This module extends Net::DNS::Dynamic::Proxyserver. See that module's documentation for further options.

=head1 AUTHOR

David Watson <terminalfool@yahoo.com>

=head1 SEE ALSO

scripts/adfilter.pl in the distribution

=head1 COPYRIGHT AND LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
