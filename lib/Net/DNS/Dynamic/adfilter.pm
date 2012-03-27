package Net::DNS::Dynamic::Adfilter;

our $VERSION = '0.02';

use Moose;
use LWP::Simple;
use IO::Socket::INET;
use Carp qw( croak );

extends 'Net::DNS::Dynamic::Proxyserver';

has ask_adhosts=> ( is => 'ro', isa => 'HashRef', required => 0 );
has pgl_url=> ( is => 'rw', isa => 'Str', required => 0, default => 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&&mimetype=plaintext' );
has adhosts=> ( is => 'rw', isa => 'Str', required => 0, default => '/var/named/adhosts' );
has morehosts=> ( is => 'rw', isa => 'Str', required => 0, default => '/var/named/morehosts' );

override 'run' => sub {

	my ( $self ) = shift;

	my $sock = IO::Socket::INET->new(
		PeerAddr=> "example.com",
		PeerPort=> 80,
		Proto   => "tcp");
	my $localip = $sock->sockhost;

	system('networksetup -setdnsservers "Wi-Fi" 127.0.0.1');
	system('networksetup -setsearchdomains "Wi-Fi" localhost');

	$self->log("Nameserver accessible locally @ $localip; localhost now queries (dns:127.0.0.1)", 1);

	$self->nameserver->main_loop;
};

override 'reply_handler' => sub {

	my ($self, $qname, $qclass, $qtype, $peerhost, $query, $conn) = @_;

	my ($rcode, @ans, @auth, @add);

	$self->log("received query from $peerhost: qtype '$qtype', qname '$qname'");

	# see if we can answer the question from hosts listings
	#
	if ($qtype eq 'A' || $qtype eq 'PTR') {
    
		if (my $ip = $self->query_hosts( $qname, $qtype )) {

			$self->log("[local host listings] resolved $qname to $ip NOERROR");

			my ($ttl, $rdata) = (($self->ask_adhosts->{ttl} ? $self->ask_adhosts->{ttl} : 86400), $ip );
        
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
	$self->addrs({ $self->parse_hosts() }); # adhosts, morehosts
};

before 'signal_handler' => sub {
	my ( $self ) = shift;
	system('networksetup -setdnsservers "Wi-Fi" empty');
	system('networksetup -setsearchdomains "Wi-Fi" empty');
};

sub query_hosts {
	my ( $self, $qname, $qtype ) = @_;

	$qname =~ s/^.*\.(\w+\.\w+)$/$1/i;
  
	return $self->search_ip_by_hostname( $qname ) if $qtype eq 'A';
	return $self->search_hostname_by_ip( $qname ) if $qtype eq 'PTR';
}

sub parse_hosts {
	my ( $self ) = shift;

	return unless $self->ask_adhosts;

	my %addrs = %{$self->addrs};
	my %names;

	my $age = -M $self->adhosts || 0;

	unless ($age < 7) {
	        $self->log("refreshing $self->{adhosts} file", 1);
	        getstore($self->pgl_url, $self->adhosts);
	}

	foreach my $hostsfile ($self->adhosts, $self->morehosts) {

		if (-e $hostsfile) {
		
			open(HOSTS, $hostsfile) or croak "cant open $hostsfile file: $!";

			while (<HOSTS>) {
    
				chomp;
				next if /^\s*#/;# skip comments
				next if /^$/; # skip empty lines
				s/\s*#.*$//;# delete in-line comments and preceding whitespace

				$names{$_}++;
			}

			close(HOSTS);
		}
	}

	push @{$addrs{'127.0.0.1'}}, $_ foreach (keys %names);

	return %addrs;
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

Ad domains are written to /var/named/adhosts and are refreshed with each invocation 
from pgl.yoyo.org/adservers.

An addendum of adhosts is parsed from /var/named/morehosts if found. File should conform 
to a one host per line format:

#secondary host list
googlesyndication.com
facebook.com
twitter.com
...

Once running, local net dns queries can be addressed to the host's ip. This ip is 
echoed to stdout.

=head1 SYNOPSIS

 my $adfilter = Net::DNS::Dynamic::Adfilter->new(

     ask_pgl_hosts => { ttl => 86400 },		#default time to live in seconds
     adhosts => '/var/named/adhosts'    	#default path to pgl hosts
     morehosts => '/var/named/morehosts'	#default path to secondary hosts

     ask_etc_hosts => { ttl => 86400 },	        #if set, parse /etc/hosts as well

 );

 $adfilter->run();


=head1 AUTHOR

David Watson <terminalfool@yahoo.com>

=head1 SEE ALSO

scripts/adfilter.pl in the distribution

Net::DNS::Dynamic::Proxyserver

=head1 COPYRIGHT AND LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

