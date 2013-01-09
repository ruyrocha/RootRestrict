package Cpanel::Security::Policy::RootRestrict;

# cpanel - Cpanel/Security/Policy/RootRestrict.pm
#
# Copyright (c) 2011-2012 Ruy Rocha <admin@ruyrocha.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in the
# Software without restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the
# following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
# USE OR OTHER DEALINGS IN THE SOFTWARE.
#

use base 'Cpanel::SecurityPolicy::Base';

# Define here your allowed remote addresses
our @allowed_ips = ('69.x.x.x', '192.x.x.x');

sub new {
  my ($class) = @_;

  # Compiler does not necessarily properly load the base class.
  unless ( exists $INC{'Cpanel/SecurityPolicy/Base.pm'} ) {
    eval 'require Cpanel::SecurityPolicy::Base;';
  }
  return Cpanel::SecurityPolicy::Base->init( __PACKAGE__, 20 );
}

sub fails {
  my ( $self , $sec_ctxt, $cpconf ) = @_;

  if ( $sec_ctxt->{'appname'} eq 'whostmgrd' && $sec_ctxt->{'user'} eq 'root' ) {
    return _ip_passes($sec_ctxt->{'remoteip'});
  }

  return 0;
}

# Return true if this address is valid, false otherwise.
sub _ip_passes {
  my $remote_ip = shift;

  if ( !$remote_ip ) {
    Carp::confess("I am missing the users remote ip.  Security Policy requires exec termination.");
  }

  return 1 if !grep(/$remote_ip$/, @allowed_ips);

  return 0;
}

1;
