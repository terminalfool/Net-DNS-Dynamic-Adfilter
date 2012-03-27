
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME         => 'Net::DNS::Dynamic::Adfilter',
    VERSION_FROM => 'lib/Net/DNS/Dynamic/Adfilter.pm', # finds \$VERSION
    AUTHOR       => 'David Watson (terminalfool@yahoo.com)',
    ABSTRACT     => 'A Perl nameserver for the purpose of filtering advertising',
    PREREQ_PM    => {
                     'Test::Simple' => 0.44,
                    },
);
