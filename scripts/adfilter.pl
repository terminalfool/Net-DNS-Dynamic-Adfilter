#!/usr/bin/env perl

use lib "lib/";

use strict;
use warnings;

use Net::DNS::Dynamic::Adfilter 0.01;

use Getopt::Long;
use Pod::Usage;

our $VERSION = '0.01';

my $debug 				= 0;
my $verbose				= 0;
my $help				= 0;
my $host 				= undef;
my $port				= undef;
my $background			= 0;
my $ask_etc_hosts		= undef;
my $ask_pgl_hosts		= 3600;
my $uid					= undef;
my $gid					= undef;
my $nameserver			= undef;
my $nameserver_port		= 0;

GetOptions(
    'debug|d'			=> \$debug,
    'verbose|v'			=> \$verbose,
    'help|?|h'			=> \$help,
    'host=s'			=> \$host,
    'port|p=s'			=> \$port,
    'background|bg'		=> \$background,
	'etc=s'				=> \$ask_etc_hosts,
	'pgl=s'				=> \$ask_pgl_hosts,
	'uid|u=s'			=> \$uid,
	'gid|g=s'			=> \$gid,
	'nameserver|ns=s'	=> \$nameserver,
);

pod2usage(1) if $help;

fork && exit if $background;

($nameserver, $nameserver_port) = split(':', $nameserver) if $nameserver && $nameserver =~ /\:/;

my $args = {};

$args->{debug}				= ($verbose ? 1 : ($debug ? 3 : 0));
$args->{host}				= $host if $host;
$args->{port}				= $port if $port;
$args->{uid}				= $uid if $uid;
$args->{gid}				= $gid if $gid;
$args->{nameservers}		= [ $nameserver ] if $nameserver;
$args->{nameservers_port} 	= $nameserver_port if $nameserver_port;
$args->{ask_etc_hosts} 		= { etc => $ask_etc_hosts } if $ask_etc_hosts;
$args->{ask_pgl_hosts} 		= { pgl => $ask_pgl_hosts } if $ask_pgl_hosts;

Net::DNS::Dynamic::Adfilter->new( $args )->run();

=head1 NAME

adfilter.pl - A dynamic DNS-based ad filter

=head1 SYNOPSIS

adfilter.pl [options]

 Options:
   -h  -help          display this help
   -v  -verbose       show server activity
   -d  -debug         enable debug mode
       -host          host (defaults to all)
   -p  -port          port (defaults to 53)
   -u  -uid           run with user id
   -g  -gid           run with group id
   -bg -background    run the process in the background
       -etc           use /etc/hosts to answer DNS queries with specified ttl (seconds)
       -pgl           use pgl.yoyo.org host list to answer DNS queries with specified ttl (defaults to 3600 seconds)
   -ns -nameserver    forward queries to this nameserver (<ip>:<port>)
       
 See also:
   perldoc Net::DNS::Dynamic::Adfilter

=head1 DESCRIPTION

This script implements a dynamic DNS proxy server for the purpose of filtering advertisements. 
See Net::DNS::Dynamic::Adfilter for more information.

=head1 AUTHOR

David Watson <terminalfool@yahoo.com>

=head1 COPYRIGHT

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

