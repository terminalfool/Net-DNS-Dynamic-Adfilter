use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME         => 'Net::DNS::Dynamic::Adfilter',
    VERSION_FROM => 'lib/Net/DNS/Dynamic/Adfilter.pm', # finds \$VERSION
    AUTHOR       => 'David Watson (terminalfool@yahoo.com)',
    ABSTRACT     => 'A DNS ad filter',
    INST_SCRIPT  => 'scripts/',
    INSTALLSCRIPT=> '/usr/local/bin',

    PREREQ_PM    => {
                     'Carp'             => 1.17,
                     'LWP::Simple'      => 5.835,
                     'IO::Socket::INET' => 1.31,
		     'Net::DNS::Dynamic::Proxyserver' => 1.1,
                     'Test::Simple' => 0.44,
                    },
);
