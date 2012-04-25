# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Net::DNS::Dynamic::Adfilter',
    AUTHOR       => 'David Watson (dwatson@cpan.org)',
    VERSION_FROM => 'lib/Net/DNS/Dynamic/Adfilter.pm', # finds \$VERSION
    ABSTRACT     => 'A DNS ad filter',
    INST_SCRIPT  => 'scripts/',
    INSTALLSCRIPT=> '/usr/local/bin',
    LICENSE      => 'perl',
    PREREQ_PM    => {
                     'LWP::Simple'      => 5.835,
                     'IO::Socket::INET' => 1.31,
		     'Net::DNS::Dynamic::Proxyserver' => 1.1,
                     'Test::Simple' => 0.44,
                    },
);
