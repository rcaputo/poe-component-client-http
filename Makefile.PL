#!/usr/bin/perl
# $Id$

use ExtUtils::MakeMaker;

WriteMakefile
  ( NAME         => 'POE::Component::Client::HTTP',
    AUTHOR       => 'Rocco Caputo <troc+poe@netrus.net>',
    ABSTRACT     => 'POE component for non-blocking/concurrent HTTP queries.',
    VERSION_FROM => 'POE/Component/Client/HTTP.pm',
    dist         => { 'COMPRESS' => 'gzip -9f',
                      'SUFFIX'   => 'gz',
                    },
    PREREQ_PM    => { POE            => 0.1106,
                      HTTP::Request  => 1.27,
                      HTTP::Response => 1.33,
                    },
  );
