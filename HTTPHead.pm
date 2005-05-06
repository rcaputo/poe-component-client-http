package POE::Filter::HTTPHead_Line;
use strict;

use HTTP::Response;

sub FRAMING_BUFFER   () { 0 }
sub CURRENT_STATE    () { 1 }
sub WORK_RESPONSE    () { 2 }
sub PROTOCOL_VERSION () { 3 }

sub STATE_STATUS () { 0x00 }  # waiting for a status line
sub STATE_HEADER () { 0x02 }  # gotten status, looking for header or end

sub DEBUG () { 0 }

sub new {
  my $type = shift;

  my $self =
    bless [ [],			    # FRAMING_BUFFER
            STATE_STATUS,	    # CURRENT_STATE
	    undef,		    # WORK_RESPONSE
	    "0.9",		    # PROTOCOL_VERSION
          ], $type;

  $self;
}

sub get_one_start {
  my ($self, $chunks) = @_;

  push (@{$self->[FRAMING_BUFFER]}, @$chunks);
  #warn "now got ", scalar @{$self->[FRAMING_BUFFER]}, " lines";
}

sub get_one {
  my $self = shift;

  #warn "in get_one";
  while (defined (my $line = shift (@{$self->[FRAMING_BUFFER]}))) {
      DEBUG and warn "LINE $line";
      if ($self->[CURRENT_STATE] == STATE_STATUS) {
	 DEBUG and warn "in status";
	 #expect a status line
	 if ($line =~ m|^(?:HTTP/(\d+\.\d+) )?(\d{3})(?: (.+))?$|) {
	    $self->[PROTOCOL_VERSION] = $1
		if (defined $1);
	    $self->[WORK_RESPONSE] = HTTP::Response->new ($2, $3);
	    $self->[CURRENT_STATE] = STATE_HEADER;
	 } else {
	    return [undef];
	    #return [HTTP::Response->new ('500', 'Bad Response')];
	 }
      } else {
	 if ($line eq '') {
	    $self->[CURRENT_STATE] = STATE_STATUS;
	    DEBUG and warn "return response";
	    return [$self->[WORK_RESPONSE]];
	 }
	 DEBUG and warn "in headers";
	 unless (@{$self->[FRAMING_BUFFER]} > 0) {
	    unshift (@{$self->[FRAMING_BUFFER]}, $line);
	    return [];
	 }
	 DEBUG and warn "got more lines";
	 while ($self->[FRAMING_BUFFER]->[0] =~ /^[\t ]/) {
	    my $next_line = shift (@{$self->[FRAMING_BUFFER]});
	    $next_line =~ s/^[\t ]+//;
	    $line .= $next_line;
	 }
	 #warn "unfolded one: $line";
	 if ($line =~ /^([^\x00-\x19()<>@,;:\\"\/\[\]\?={} \t]+):\s*([^\x00-\x07\x09-\x19]+)$/) {
	    $self->[WORK_RESPONSE]->header($1, $2)
	 }
      }
  }
  return [];
}

=for future

sub put {
  my ($self, $responses) = @_;
  my $out;

  foreach my $response (@$responses) {
    $out = $response->as_string
  }

  $out;
}

=cut

sub get_pending {
  my $self = shift;
  return $self->[FRAMING_BUFFER];
}

package POE::Filter::HTTPHead;
use strict;

=head1 NAME

POE::Filter::HTTPHead - filter data as HTTP::Response objects

=head1 SYNOPSYS

       $filter = POE::Filter::HTTPHead->new();
        $arrayref_of_response_objects =
               $filter->get($arrayref_of_raw_chunks_from_driver);

       $arrayref_of_leftovers = $filter->get_pending();

=head1 DESCRIPTION

The HTTPHead filter turns stream data that has the appropriate format
into a HTTP::Response object. In an all-POE world, this would sit on
the other end of a connection as L<POE::Filter::HTTPD>

=cut

use vars qw($VERSION);
$VERSION = '0.01';

use base qw(POE::Filter::Stackable);
use POE::Filter::Line;

sub new {
  my $type = shift;

  my $self = $type->SUPER::new (Filters => [
      POE::Filter::Line->new,
      POE::Filter::HTTPHead_Line->new,
    ],
  );

  return bless $self, $type;
}

=head1 METHODS

See L<POE::Filter> for documentation of the public API.

=cut

sub get_pending {
  my $self = shift;

  my @pending = map {"$_\n"} @{$self->[0]->[1]->get_pending};
  my $lines = $self->[0]->[0]->get_pending;
  push (@pending, @$lines) if (defined $lines);

  return \@pending;
}

=for future?

sub put {
  my $self = shift;

  return $self->[0]->[1]->put (@_);
}

=cut

1;
