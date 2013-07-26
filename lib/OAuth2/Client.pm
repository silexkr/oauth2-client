package OAuth2::Client;

use Moose;
use DateTime;
use HTTP::Request;
use JSON::XS;
use URI::QueryParam;
use URI;

with 'OAuth2::Traits::Client';

our @GRANT_TYPES = (
    'Authorization Code',
    'Implicit',
    'Resource Owner Password Credentials',
    'Client Credentials',
    'Refresh Token'
);
our @RESPONSE_TYPES = qw/code token/;

has [qw/client_id client_secret authorization_endpoint token_endpoint/] => (
    is  => 'ro',
    isa => 'Str'
);

has [qw/access_token token_type refresh_token scope/] => (
    is      => 'rw',
    isa     => 'Str',
    default => '',
);

has 'expires' => (
    is  => 'rw',
    isa => 'DateTime'
);

sub authorization_request {
    my ($self, %args) = @_;

    my $response_type = $args{response_type};

    die "Unknown Reponse-Type"
      unless grep { $response_type eq $_ } @RESPONSE_TYPES;

    my ($req, $res, $data, %query_params);
    $req = HTTP::Request->new(GET => $self->authorization_endpoint);

    ## TODO: consider `token` response type

    %query_params = (
        response_type => $response_type,
        client_id     => $self->client_id,
    );

    $query_params{redirect_uri} = $args{redirect_uri} if $args{redirect_uri};
    $query_params{scope}        = $args{scope} if $args{scope};
    $query_params{state}        = $args{state} if $args{state};

    $req->uri->query_form(%query_params);
    return $req;
}

sub token_request {
    my ($self, %args) = @_;

    my $grant_type = $args{grant_type};

    die "Unknown Grant-Type"
      unless grep { $grant_type eq $_ } @GRANT_TYPES;

    if ($grant_type ne 'Refresh Token'
          and defined $self->expires
          and $self->expires->epoch < DateTime->now->epoch) {
        die "Failed to refresh-token" unless $self->_refresh_token();
    }

    my ($req, $res, $data, %query_params);
    $req = HTTP::Request->new(POST => $self->token_endpoint);

    my $credentials = $self->basic_credentials($self->client_id, $self->client_secret);
    $req->header(Authorization => $credentials);

    if ($grant_type eq 'Authorization Code') {
        ## GRANT_TYPE, CODE, REDIRECT_URI, CLIENT_ID

        die "Invalid Argument" unless $args{code} && $args{redirect_uri};

        %query_params = (
            code         => $args{code},
            grant_type   => 'authorization_code',
            redirect_uri => $args{redirect_uri},
        );
    } elsif ($grant_type eq 'Implicit') {
    } elsif ($grant_type eq 'Resource Owner Password Credentials') {
        # GRANT_TYPE, USERNAME, PASSWORD, scope
        %query_params = (
            grant_type => 'password',
            username   => $args{username},
            password   => $args{password},
        );
        $query_params{scope} = $args{scope} if $args{scope};
    } elsif ($grant_type eq 'Client Credentials') {
        # GRANT_TYPE, scope
        $query_params{grant_type} = 'client_credentials';
        $query_params{scope} = $args{scope} if $args{scope};
    } elsif ($grant_type eq 'Refresh Token') {
        # GRANT_TYPE, REFRESH_TOKEN, scope

        die "refresh_token is required" unless $args{refresh_token};

        %query_params = (
            grant_type    => 'refresh_token',
            refresh_token => $args{refresh_token},
        );
        $query_params{scope} = $args{scope} if $args{scope};
    } else {
        die "Invalid Grant-Type";
    }

    $req->uri->query_form(%query_params);
    return $req;
}

sub token {
    my ($self, $req) = @_;

    my $grant_type = $req->uri->query_param('grant_type');

    return if $grant_type ne 'client_credentials' && $grant_type ne 'password';

    $req->header('Accept',       'application/json');
    $req->header('Content-Type', 'application/x-www-form-urlencoded');

    ## query_params in URI is also fine.
    $req->content($req->uri->query);
    $req->uri->query_form({});

    my $res = $self->ua->request($req);
    $self->parse_response($res);
    return $self->access_token;
}

sub parse_response {
    my ($self, $res) = @_;

    die "Unsupported Content-Type" if $res->header('Content-Type') ne 'application/json';

    my $data = decode_json($res->content);

    if ($res->is_success) {
        ### TODO: validate successful response
        ### http://tools.ietf.org/html/rfc6749#section-5.1
        $self->access_token($data->{access_token});
        $self->token_type($data->{token_type});

        $self->refresh_token($data->{refresh_token}) if $data->{refresh_token};
        $self->scope($data->{scope})                 if $data->{scope};
        if (my $expires_in = $data->{expires_in}) {
            my $epoch = DateTime->now->epoch;
            my $dt    = DateTime->from_epoch(epoch => $epoch + $expires_in);
            $self->expires($dt);
        }
    }

    return $data;
}

sub _refresh_token {
    my ($self, $refresh_token) = @_;

    my $req = $self->token_request(
        grant_type    => 'Refresh Token',
        refresh_token => $refresh_token || $self->refresh_token
    );
    my $res = $self->ua->request($req);
    $self->parse_response($res);
    return $res->is_success;
}

__PACKAGE__->meta->make_immutable;

1;

=pod

=encoding utf-8

=head1 NAME

=haed1 SYNOPSIS

    use OAuth2::Client;
    my $client = OAuth2::Client->new(
        client_id              => '5c4b5f41-f0f2-4fdd-aa7a-b161b4ee04d7',
        client_secret          => 'q76UgVkXi1VE50Ettc1TY2kMpgoJmqzWmCmy',
        authorization_endpoint => 'http://auth.silex.kr:5000/oauth/authorize',
        token_endpoint         => 'http://auth.silex.kr:5000/oauth/token',
    );

    my $req;    # $req is an HTTP::Request object
    $req = $client->authorization_request(
        response_type => 'code',
        redirect_uri  => 'http://restore.e-crf.co.kr:5001/',
        state         => 'xyz'
    );

    $req = $client->token_request(
        grant_type   => 'Authorization Code',
        code         => 'aXW2c6bYz',
        redirect_uri => 'http://restore.e-crf.co.kr:5001/'
    );

    $req = $client->token_request(
        grant_type => 'Resource Owner Password Credentials',
        username   => 'aanoaa',
        password   => '123456'
    );

    $token = $client->token($req);    # cause, password grant_type

=cut
