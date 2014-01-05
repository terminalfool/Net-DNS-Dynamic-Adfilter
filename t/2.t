use Data::Dumper;

use Test;
BEGIN { plan tests => 1 };

use lib "../lib/";
use Net::DNS::Dynamic::Adfilter;
use Net::DNS::Resolver;

$SIG{CHLD} = 'IGNORE';

my $port = int(rand(9999)) + 10000;

my $adfilter = Net::DNS::Dynamic::Adfilter->new( host => '127.0.0.1', port => $port, nameservers => [ '8.8.8.8', '8.8.4.4' ] );

my $pid = fork();

unless ($pid) {

	$adfilter->run();
	exit;
}

my $res = Net::DNS::Resolver->new(
	nameservers => [ '127.0.0.1' ],
	port		=> $port,
	recurse     => 1,
	debug       => 0,
);

my $search = $res->search('www.perl.org', 'A');

ok($search->isa('Net::DNS::Packet'));

kill 3, $pid;

