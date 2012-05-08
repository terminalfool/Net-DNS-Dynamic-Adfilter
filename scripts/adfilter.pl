#!/usr/bin/env perl

use lib "../lib/";

use strict;
use warnings;

use Net::DNS::Dynamic::Adfilter 0.064;

use Getopt::Long;
use Pod::Usage;

our $VERSION = '0.064';

my $debug 	      = 0;
my $verbose	      = 0;
my $help	      = 0;
my $host 	      = '127.0.0.1';
my $port	      = '53';
my $background	      = 0;
my $ask_etc_hosts     = undef;
my $uid		      = undef;
my $gid		      = undef;
my $nameserver	      = undef;
my $nameserver_port   = 0;

#my $pgl_hosts_url         = 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&&mimetype=plaintext';
my $pgl_hosts_url          = 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&startdate[day]=&startdate[month]=&startdate[year]=&mimetype=plaintext';
my $pgl_hosts_path         = '/var/named/pgl-adblock.txt';
my $pgl_hosts_refresh      = 7;

my $fanboy_hosts_url       = 'http://www.fanboy.co.nz/fanboy-adblock.txt';
my $fanboy_hosts_path      = '/var/named/fanboy-adblock.txt';
my $fanboy_hosts_refresh   = 4;

my $easylist_hosts_url     = 'https://easylist-downloads.adblockplus.org/easylist.txt';
my $easylist_hosts_path    = '/var/named/easylist-adblock.txt';
my $easylist_hosts_refresh = 5;

my $more_hosts_path      = '/var/named/morehosts';

GetOptions(
    'debug|d'	               => \$debug,
    'verbose|v'	               => \$verbose,
    'help|?|h'	               => \$help,
    'host=s'	               => \$host,
    'port|p=s'	               => \$port,
    'background|bg'            => \$background,
    'etc=s'	               => \$ask_etc_hosts,
    'uid|u=s'	               => \$uid,
    'gid|g=s'	               => \$gid,
    'nameserver|ns=s'          => \$nameserver,

    'pgl_hosts_url|pgl=s'      => \$pgl_hosts_url,
    'pgl_hosts_path=s'         => \$pgl_hosts_path,
    'pgl_hosts_refresh=s'      => \$pgl_hosts_refresh,

    'fanboy_hosts_url|pgl=s'   => \$fanboy_hosts_url,
    'fanboy_hosts_path=s'      => \$fanboy_hosts_path,
    'fanboy_hosts_refresh=s'   => \$fanboy_hosts_refresh,

    'easylist_hosts_url|ez=s'  => \$easylist_hosts_url,
    'easylist_hosts_path=s'    => \$easylist_hosts_path,
    'easylist_hosts_refresh=s' => \$easylist_hosts_refresh,

    'more_hosts_path=s'      => \$more_hosts_path,
);

pod2usage(1) if $help;

fork && exit if $background;

($nameserver, $nameserver_port) = split(':', $nameserver) if $nameserver && $nameserver =~ /\:/;

my $args = {};

$args->{debug}		  = ($verbose ? 1 : ($debug ? 3 : 0));
$args->{host}		  = $host if $host;
$args->{port}		  = $port if $port;
$args->{uid}	          = $uid if $uid;
$args->{gid}		  = $gid if $gid;
$args->{nameservers}	  = [ $nameserver ] if $nameserver;
$args->{nameservers_port} = $nameserver_port if $nameserver_port;
$args->{ask_etc_hosts} 	  = { etc => $ask_etc_hosts } if $ask_etc_hosts;

$args->{ask_pgl_hosts} = { url => $pgl_hosts_url, 
			   path => $pgl_hosts_path,
			   refresh => $pgl_hosts_refresh,
		         };

$args->{ask_fanboy_hosts} = { url => $fanboy_hosts_url, 
			   path => $fanboy_hosts_path,
			   refresh => $fanboy_hosts_refresh,
		         };

$args->{ask_easylist_hosts} = { url => $easylist_hosts_url, 
			   path => $easylist_hosts_path,
			   refresh => $easylist_hosts_refresh,
		         };

$args->{ask_more_hosts} = { path => $more_hosts_path };

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
   -u   -uid                    run with user id
   -g   -gid                    run with group id
   -bg  -background             run the process in the background
        -etc                    use /etc/hosts to answer DNS queries with specified ttl (seconds)
   -ns  -nameserver             forward queries to this nameserver (<ip>:<port>)

   -pgl -pgl_hosts_url          url to single column adhosts text
                                  defaults to http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&&mimetype=plaintext
        -pgl_hosts_path         path to local copy of adhosts text
        -pgl_hosts_refresh      local copy refresh value (days--defaults to 7)

    -fb -fanboy_hosts_url       url to single column adhosts text
                                  defaults to http://www.fanboy.co.nz/fanboy-adblock.txt
        -fanboy_hosts_path      path to local copy of fanboy hosts text
        -fanboy_hosts_refresh   local copy refresh value (days--defaults to 4)

    -ez -easylist_hosts_url     url to single column adhosts text
                                  defaults to https://easylist-downloads.adblockplus.org/easylist.txt
        -easylist_hosts_path    path to local copy of fanboy hosts text
        -easylist_hosts_refresh local copy refresh value (days--defaults to 4)

        -more_hosts_path        path to optional single column list of adhosts

  Accept the defaults and run in background:
     sudo perl adfilter.pl -bg
     # you must manually kill this process

See also:
   perldoc Net::DNS::Dynamic::Adfilter

=head1 DESCRIPTION

This script implements a dynamic DNS proxy server for the purpose of filtering advertisements. 
See Net::DNS::Dynamic::Adfilter for more information.

=head1 AUTHOR

David Watson <dwatson@cpan.org>

=head1 COPYRIGHT

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
