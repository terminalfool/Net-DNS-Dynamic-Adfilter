# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
use inc::Module::Install;
author 'David Watson (terminalfool@yahoo.com)';
license 'perl';

auto_set_repository;
auto_license;

WriteMakefile(
    NAME         => 'Net::DNS::Dynamic::Adfilter',
    VERSION_FROM => 'lib/Net/DNS/Dynamic/Adfilter.pm', # finds \$VERSION
    ABSTRACT     => 'A DNS ad filter',
    INST_SCRIPT  => 'scripts/',
    INSTALLSCRIPT=> '/usr/local/bin',
    PREREQ_PM    => {
                     'LWP::Simple'      => 5.835,
                     'IO::Socket::INET' => 1.31,
		     'Net::DNS::Dynamic::Proxyserver' => 1.1,
                     'Test::Simple' => 0.44,
                    },
);
