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
sub RESPONSE_SIZE    () { 5 }

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

  #warn "GOT MORE DATA";
  push (@{$self->[FRAMING_BUFFER]}, @$chunks);
    #warn "NUMBER OF CHUNKS is now ", scalar @{$self->[FRAMING_BUFFER]};
}

sub get_one {
  my $self = shift;

  my $retval = [];
  while (defined (my $chunk = shift (@{$self->[FRAMING_BUFFER]}))) {
    #warn "CHUNK IS SIZE ", length($chunk);
    #warn join (",", map {sprintf("%02X", ord($_))} split (//, substr ($chunk, 0, 10))), "\n";
    #warn "NUMBER OF CHUNKS is ", scalar @{$self->[FRAMING_BUFFER]};
    #warn "STATE is ", $self->[CURRENT_STATE];
    if ($self->[CURRENT_STATE] == STATE_SIZE) {
      #warn "FINDING CHUNK LENGTH";
      if ($chunk !~ /.\015?\012/s) {
	#warn "SPECIAL CASE";
	if (@{$self->[FRAMING_BUFFER]} == 0) {
	  #warn "pushing $chunk back";
      	  unshift (@{$self->[FRAMING_BUFFER]}, $chunk);
	  return $retval;
	} else {
	  $chunk .= shift (@{$self->[FRAMING_BUFFER]});
	  #warn "added to $chunk";
	}
      }
      if ($chunk =~ s/^($HEX+)(?:;.*)?\015?\012//s) {
	my $length = hex($1);
	#warn "GOT CHUNK OF LENGTH $length";
	$self->[CHUNK_SIZE] = $length;
	$self->[RESPONSE_SIZE] += $length;
	if ($length == 0) {
	  $self->[CURRENT_STATE] = STATE_TRAILER;
	} else {
	  $self->[CURRENT_STATE] = STATE_DATA;
	}
      } else {
	#warn "DIDN'T FIND CHUNK LENGTH";
	return $retval;
      }
    }
    if ($self->[CURRENT_STATE] == STATE_DATA) {
      my $len = $self->[CHUNK_SIZE] - length ($self->[CHUNK_BUFFER]);
      #warn "going for length ", $self->[CHUNK_SIZE], " (need $len more)";
      my $newchunk = delete $self->[CHUNK_BUFFER];
      $newchunk .= substr ($chunk, 0, $len, '');
      #warn "got " . length($newchunk) . " bytes of data";
      if (length $newchunk != $self->[CHUNK_SIZE]) {
	#smaller, so wait
	$self->[CHUNK_BUFFER] = $newchunk;
	next;
      }
      $self->[CURRENT_STATE] = STATE_SIZE;
      #warn "BACK TO FINDING CHUNK SIZE $chunk";
      if (length ($chunk) > 0) {
	#warn "we still have a bit";
	#warn "'", substr ($chunk, 0, 10), "'";
	$chunk =~ s/^\015?\012//s;
	#warn "'", substr ($chunk, 0, 10), "'";
	unshift (@{$self->[FRAMING_BUFFER]}, $chunk);
      }
      push @$retval, $newchunk;
      #return [$newchunk];
    }
    if ($self->[CURRENT_STATE] == STATE_TRAILER) {
      if ($chunk =~ /^\015?\012/s) {
	#warn "SETTING CONTENT LENGTH";
	#$self->[TRAILER_RESPONSE]->header ('Content-Length',
					   #$self->[RESPONSE_SIZE]);
	my $response = delete $self->[TRAILER_RESPONSE];
	push (@$retval, $response);
	#warn "returning ", scalar @$retval, "responses";
	return $retval;
      }
      if ($chunk =~ s/([-\w]+):\s*(?:.*?)\015?\012//s) {
	$self->[TRAILER_RESPONSE]->header ($1, $2);
      }
    }
  }
  return $retval;
}

sub put {
  die "not implemented yet";
}

sub get_pending {
  my $self = shift;
  return $self->[FRAMING_BUFFER] if @{$self->[FRAMING_BUFFER]};
  return undef;
}
