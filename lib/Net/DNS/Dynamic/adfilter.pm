package Net::DNS::Dynamic::Adfilter;

our $VERSION = '0.04';

use Moose;
use LWP::Simple;
use IO::Socket::INET;
use Carp qw( croak );

extends 'Net::DNS::Dynamic::Proxyserver';

has ask_adhosts=> ( is => 'ro', isa => 'HashRef', required => 0 );

override 'run' => sub {

	my ( $self ) = shift;

	my $sock = IO::Socket::INET->new(
		PeerAddr=> "example.com",
		PeerPort=> 80,
		Proto   => "tcp");
	my $localip = $sock->sockhost;

#--switch dns settings on mac osx wireless interface--
	system("networksetup -setdnsservers \"Wi-Fi\" $localip");
	system("networksetup -setsearchdomains \"Wi-Fi\" localhost");
#--

	$self->log("Nameserver accessible locally @ $localip", 1);

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

                        my $refresh = $self->ask_adhosts->{adhosts_refresh} ? $self->ask_adhosts->{adhosts_refresh} : $self->ask_etc_hosts->{ttl} ? $self->ask_etc_hosts->{ttl} : 7;

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
	$self->addrs({ $self->parse_hosts() }); # adhosts, morehosts
};

#--restore dns settings on mac osx wireless interface--
before 'signal_handler' => sub {
	my ( $self ) = shift;
	system('networksetup -setdnsservers "Wi-Fi" empty');
	system('networksetup -setsearchdomains "Wi-Fi" empty');
};
#--

sub query_hosts {
	my ( $self, $qname, $qtype ) = @_;

	$qname =~ s/^.*\.(\w+\.\w+)$/$1/i if $qtype eq 'A';
  
	return $self->search_ip_by_hostname( $qname ) if $qtype eq 'A';
	return $self->search_hostname_by_ip( $qname ) if $qtype eq 'PTR';
}

sub parse_hosts {
	my ( $self ) = shift;

	return unless $self->ask_adhosts;
	return unless $self->ask_adhosts->{adhosts_refresh};

	my %addrs = %{$self->addrs};
	my %names;

	my $age = -M $self->ask_adhosts->{adhosts_path} || 0;

	if ($age > $self->ask_adhosts->{adhosts_refresh}) {
	        $self->log("refreshing $self->ask_adhosts->{adhosts_path} file", 1);
	        getstore($self->ask_adhosts->{adhosts_url}, $self->ask_adhosts->{adhosts_path});
	}

	foreach my $hostsfile ($self->ask_adhosts->{adhosts_path}, $self->ask_adhosts->{morehosts_path}) {

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
the loopback address 127.0.0.1. Any other queries are forwarded downstream to a 
specified list of nameservers or those defined in /etc/resolv.conf. The module can 
also load and resolve any /etc/hosts definitions that might exist. 

Ad domains are accessed from pgl.yoyo.org/adservers and are refreshed periodically. 
A static list of ad domains can also be specified. Ad host listings must conform to a 
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
                     adhosts_refresh => 7,                       #ttl in days
                     adhosts_url => 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&&mimetype=plaintext',
                     adhosts_path => '/var/named/adhosts',       #path to ad hosts
                     morehosts_path => '/var/named/morehosts',   #path to secondary hosts
                    },
     ask_etc_hosts => { ttl => 7 },	                         #if set, parse and resolve /etc/hosts as well; ttl in days
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
