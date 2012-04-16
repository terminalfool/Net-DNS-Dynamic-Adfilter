use Test;
BEGIN { plan tests => 1 }

eval { use lib "../lib/"; use Net::DNS::Dynamic::Adfilter; return 1; };
ok($@,'');
warn() if $@;
