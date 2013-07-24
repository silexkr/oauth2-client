package OAuth2::Traits::Client;

use Moose::Role;
use HTTP::Cookies;
use JSON::XS;
use LWP::UserAgent;
use MIME::Base64 'encode_base64';

requires qw/authorize token/;

has 'ua' => (
    is  => 'ro',
    isa => 'LWP::UserAgent',
    default => sub {
        my $ua = LWP::UserAgent->new(
            agent => 'OAuth2::Client',
            cookie_jar => HTTP::Cookies->new
        );

        $ua->add_handler(
            'request_prepare' => sub {
                my ($req, $ua, $h) = @_;
                if ($ENV{DEBUG}) {
                    my $req_string = $req->as_string =~ s{\n}{\n> }mgr;
                    print "> $req_string";
                }
            }
        );

        $ua->add_handler(
            'response_done' => sub {
                my ($res, $ua, $h) = @_;
                if ($ENV{DEBUG}) {
                    my $res_string = $res->as_string =~ s{\n}{\n< }mgr;
                    print "< $res_string";
                }
            }
        );

        return $ua;
    },
);

sub basic_credentials {
    my ($self, $username, $password) = @_;

    return '' unless $username && $password;
    return "Basic " . encode_base64("$username:$password", '');
}

no Moose::Role;

1;
