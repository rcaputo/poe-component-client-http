package POE::Filter::HTTPChunk;
use strict;

use Carp;
use bytes;

use HTTP::Response;

sub FRAMING_BUFFER   () { 0 }
sub CURRENT_STATE    () { 1 }
sub CHUNK_SIZE       () { 2 }
sub CHUNK_BUFFER     () { 3 }
sub TRAILER_RESPONSE () { 4 }

sub STATE_SIZE () { 0x00 }  # waiting for a status line
sub STATE_DATA () { 0x02 }  # gotten status, looking for header or end
sub STATE_TRAILER () { 0x04 }  # gotten status, looking for header or end


sub new {
  my $type = shift;
  croak "$type must be given an even number of parameters" if @_ & 1;
  my %params = @_;
  my $response = $params{'Response'};

  my $self =
    bless [ [],			    # FRAMING_BUFFER
            STATE_SIZE,		    # CURRENT_STATE
	    0,			    # CHUNK_SIZE
	    '',			    # CHUNK_BUFFER
	    $response,		    # TRAILER_RESPONSE
          ], $type;

  $self;
}

my $HEX = qr/[\dA-Fa-f]/o;

=for later

my $TEXT = qr/[^[:cntrl:]]/o;
my $qdtext = qr/[^[:cntrl:]\"]/o; #<any TEXT except <">>
my $quoted_pair = qr/\\[[:ascii:]]/o;
my $quoted_string = qr/\"(?:$qdtext|$quoted_pair)\"/o;
my $separators = "[^()<>@,;:\\"\/\[\]\?={} \t";
my $notoken = qr/(?:[[:cntrl:]$separators]/o;

my $chunk_ext_name = $token;
my $chunk_ext_val = qr/(?:$token|$quoted_string)/o;

my $chunk_extension = qr/(?:;$chunk_ext_name(?:$chunk_ext_val)?)/o;

=cut

sub get_one_start {
  my ($self, $chunks) = @_;

  push (@{$self->[FRAMING_BUFFER]}, @$chunks);
}

sub get_one {
  my $self = shift;

  while (defined (my $chunk = shift (@{$self->[FRAMING_BUFFER]}))) {
    if ($self->[CURRENT_STATE] == STATE_SIZE) {
      if ($chunk !~ /.\n/s) {
	if (@{$self->[FRAMING_BUFFER]} == 0) {
      	  unshift (@{$self->[FRAMING_BUFFER]}, $chunk);
	  return [];
	} else {
	  $chunk .= shift (@{$self->[FRAMING_BUFFER]});
	}
      }
      if ($chunk =~ s/($HEX+)(?:;.*)?\n//s) {
	my $length = hex($1);
	$self->[CHUNK_SIZE] = $length;
	if ($length == 0) {
	  $self->[CURRENT_STATE] = STATE_TRAILER;
	} else {
	  $self->[CURRENT_STATE] = STATE_DATA;
	}
      } else {
	return [];
      }
    }
    if ($self->[CURRENT_STATE] == STATE_DATA) {
      my $len = $self->[CHUNK_SIZE] - length ($self->[CHUNK_BUFFER]);
      my $newchunk = delete $self->[CHUNK_BUFFER];
      $newchunk .= substr ($chunk, 0, $len, '');
      if (length $newchunk != $self->[CHUNK_SIZE]) {
	#smaller, so wait
	$self->[CHUNK_BUFFER] = $newchunk;
	next;
      }
      $self->[CURRENT_STATE] = STATE_SIZE;
      if (length ($chunk) > 0) {
	$chunk =~ s/^\n//s;
	unshift (@{$self->[FRAMING_BUFFER]}, $chunk);
      }
      return [$newchunk];
    }
    if ($self->[CURRENT_STATE] == STATE_TRAILER) {
      if ($chunk =~ /\n/s) {
	return [];
      }
      if ($chunk =~ s/([-\w]+):\s*(?:.*?)\n//s) {
	$self->[TRAILER_RESPONSE]->header ($1, $2);
      }
    }
  }
  return [];
}

sub put {
  die "not implemented yet";
}

sub get_pending {
  my $self = shift;
  return $self->[FRAMING_BUFFER] if @{$self->[FRAMING_BUFFER]};
  return undef;
}
