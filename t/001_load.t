# -*- perl -*-

# t/001_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'Net::DNS::Dynamic::Adfilter' ); }

my $object = Net::DNS::Dynamic::Adfilter->new ();
isa_ok ($object, 'Net::DNS::Dynamic::Adfilter');


