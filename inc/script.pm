package inc::script;

use Moose;

extends 'Dist::Zilla::Plugin::MakeMaker::Awesome';

override _build_WriteMakefile_args => sub { +{
        # Add INST_SCRIPT, INSTALLSCRIPT to WriteMakefile() args
        %{ super() },
	INSTALLDIRS => 'perl',
	INST_SCRIPT => 'scripts/',
	INSTALLSCRIPT => '/usr/local/bin',
    } };

__PACKAGE__->meta->make_immutable;



