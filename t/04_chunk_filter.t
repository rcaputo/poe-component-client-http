# $Id$
# vim: filetype=perl ts=2 sw=2 expandtab

use strict;
use warnings;

use IO::Handle;
use Test::More;

sub DEBUG () { 0 }

#plan tests => 9;
plan 'no_plan';

use_ok ('POE::Filter::HTTPChunk');

my $chunk_count = 1;

autoflush STDOUT 1;
autoflush STDERR 1;

my $filter = POE::Filter::HTTPChunk->new;

while (my $line = <DATA>) {
  warn "LINE: $line";
  if (substr($line, 0, 5) eq '--end') {
    while (my $data = $filter->get_one) {
      use Data::Dumper;
      warn Dumper $data;
      last unless @$data;
    }
    my $pending = $filter->get_pending;
    warn Dumper $pending;
    $filter = POE::Filter::HTTPChunk->new;
  } else {
    $filter->get_one_start([$line]);
  }
}

__DATA__
7
chunk 1
CRAP
8
chunk 22
0
Server: Apache/1.3.31 (Unix) DAV/1.0.3 mod_gzip/1.3.26.1a PHP/4.3.5 mod_ssl/2.8.19 OpenSSL/0.9.6c
--end--
9
chunk 333

A
chunk 4444
0

--end--
d
regular chunk
25   
chunk length with trailing whitespace
0
--end--
