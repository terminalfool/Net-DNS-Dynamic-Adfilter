#!/usr/bin/env perl

use lib "../lib/";

use strict;
use warnings;

use Net::DNS::Dynamic::Adfilter 0.065;

use Getopt::Long;
use Pod::Usage;

our $VERSION = '0.065';

my $debug 	      = 0;
my $verbose	      = 0;
my $help	      = 0;
my $host 	      = '127.0.0.1';
my $port	      = '53';
my $background	      = 0;
my $nameserver	      = undef;
my $nameserver_port   = 0;

GetOptions(
    'debug|d'	               => \$debug,
    'verbose|v'	               => \$verbose,
    'help|?|h'	               => \$help,
    'host=s'	               => \$host,
    'port|p=s'	               => \$port,
    'background|bg'            => \$background,
    'nameserver|ns=s'          => \$nameserver,
);

pod2usage(1) if $help;

fork && exit if $background;

($nameserver, $nameserver_port) = split(':', $nameserver) if $nameserver && $nameserver =~ /\:/;

my $args = {};

$args->{debug}		  = ($verbose ? 1 : ($debug ? 3 : 0));
$args->{host}		  = $host if $host;
$args->{port}		  = $port if $port;
$args->{nameservers}	  = [ $nameserver ] if $nameserver;
$args->{nameservers_port} = $nameserver_port if $nameserver_port;
$args->{adblock_stack}    = [
			       { url => 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&startdate[day]=&startdate[month]=&startdate[year]=&mimetype=plaintext',
			        path => '/var/named/pgl-adblock.txt',
			        refresh => 7,
			       },
			       { url => "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
			         path => '/var/named/easyprivacy.txt',
			         refresh => 5,
			       },
			    ];
#$args->{custom_filter}	  = { path => '/var/named/morehosts' };

Net::DNS::Dynamic::Adfilter->new( $args )->run();

=head1 NAME

adfilter.pl - Sample interface script to Net::DNS::Dynamic::Adfilter

=head1 SYNOPSIS

adfilter.pl [options]

 Options:
   -h   -help                   display this help
   -v   -verbose                show server activity
   -d   -debug                  enable debug mode
        -host                   host (defaults to localhost)
   -p   -port                   port (defaults to 53)
   -bg  -background             run the process in the background
   -ns  -nameserver             forward queries to this nameserver (<ip>:<port>)

=head1 DESCRIPTION

This script implements a dynamic DNS proxy server for the purpose of filtering advertisements. 

=head1 CAVEATS

Though the module permits the use of as many lists as you like, it should be sufficient to run this script using one or two lists, accepting the defaults and running it in the background:

     sudo perl adfilter.pl -bg
     # you must manually kill this process

Edit the adblock_stack and custom_filter args to your liking.

=head1 AUTHOR

David Watson <dwatson@cpan.org>

=head1 SEE ALSO

Net::DNS::Dynamic::Adfilter

=head1 COPYRIGHT

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
