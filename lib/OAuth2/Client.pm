package OAuth2::Client;

use Moose;
use DateTime;
use HTTP::Request;
use URI::QueryParam;
use URI;

with 'OAuth2::Traits::Client';

### AC  : AuthorizationCode
### IMP : Implicit
### ROPC: ResourceOwnerPasswordCredentials
### CC  : ClientCredentials
### RT  : RefreshToken
our @GRANT_TYPES    = qw/AC IMP ROPC CC RT/;
our @RESPONSE_TYPES = qw/code token/;

has [qw/client_id client_secret authorization_endpoint token_endpoint/] => (
    is  => 'ro',
    isa => 'Str'
);

has 'accept' => (
    is      => 'ro',
    isa     => 'Str',
    default => '',
);

has [qw/access_token token_type refresh_token scope/] => (
    is      => 'rw',
    isa     => 'Str',
    default => '',
);

has 'expires_in' => (
    is  => 'rw',
    isa => 'DateTime'
);

sub authorize {
    my ($self, $response_type, %args) = @_;

    die "Unknown Reponse-Type"
      unless grep { $response_type eq $_ } @RESPONSE_TYPES;

    my ($req, $res, $data, %query_params);
    $req = HTTP::Request->new(GET => $self->authorization_endpoint);
    $req->header(Accept => $self->accept) if $self->accept;

    ## TODO: consider `token` response type

    %query_params = (
        response_type => $response_type,
        client_id     => $self->client_id,
    );

    $query_params{redirect_uri} = $args{redirect_uri} if $args{redirect_uri};
    $query_params{scope}        = $args{scope} if $args{scope};
    $query_params{state}        = $args{state} if $args{state};

    $req->uri->query_form(%query_params);
    $res = $self->ua->request($req);

    my $location = $res->header('Location');
    die "Missing Location" unless $location;

    ### TODO: validate $location
    ###   http://tools.ietf.org/html/rfc6749#section-4.1.2
    my $redirect_uri = URI->new($location);
    my $is_success = 1; $data = {};
    for my $key ($redirect_uri->query_param) {
        $data->{$key} = $redirect_uri->query_param($key);
        $is_success = 0 if $key eq 'error';
    }

    # which is better? $location(string) or $redirect_uri(URI object)?
    return ($is_success, $data, $location);
}

sub token {
    my ($self, $grant_type, %args) = @_;

    die "Unknown Grant-Type"
      unless grep { $grant_type eq $_ } @GRANT_TYPES;

    my ($req, $res, $data, %query_params);
    $req = HTTP::Request->new(GET => $self->token_endpoint);
    $req->header(Accept => $self->accept) if $self->accept;

    my $credentials = $self->basic_credentials($self->client_id, $self->client_secret);
    $req->header(Authorization => $credentials);

    if ($grant_type eq 'AC') {
        ## GRANT_TYPE, CODE, REDIRECT_URI, CLIENT_ID
        ## using Authorization header for Client Credentials instead
        ## of CLIENT_ID

        ### TODO: authorize 에서 redirect_uri 는 optional 이기 때문에
        ### redirect_uri 가 항상 넘어올 순 없다. 허놔, spec 의 응답을
        ### 보면 302 밖에 없다.

        ### http://tools.ietf.org/html/rfc6749#section-4.1.3
        ### redirect_uri
        ###   REQUIRED, if the "redirect_uri" parameter was included
        ###   in the authorization request as described in Section
        ###   4.1.1, and their values MUST be identical.

        die "Invalid Argument" unless $args{code} && $args{redirect_uri};

        %query_params = (
            code         => $args{code},
            grant_type   => 'authorization_code',
            redirect_uri => $args{redirect_uri},
        );
    } elsif ($grant_type eq 'IMP') {
    } elsif ($grant_type eq 'ROPC') {
        # GRANT_TYPE, USERNAME, PASSWORD, scope
        my $grant_type_option = $self->grant_type_option;
        %query_params = (
            grant_type => 'password',
            username   => $grant_type_option->{username},
            password   => $grant_type_option->{password},
        );
        $query_params{scope} = $args{scope} if $args{scope};
    } elsif ($grant_type eq 'CC') {
        # GRANT_TYPE, scope
        $query_params{grant_type} = 'client_credentials';
        $query_params{scope} = $args{scope} if $args{scope};
    } elsif ($grant_type eq 'RT') {
        # GRANT_TYPE, REFRESH_TOKEN, scope

        die "refresh_token is required" unless $self->refresh_token;

        %query_params = (
            grant_type    => 'refresh_token',
            refresh_token => $self->refresh_token,
        );
        $query_params{scope} = $args{scope} if $args{scope};
    } else {
        die "Invalid Grant-Type";
    }

    $req->uri->query_form(%query_params);
    $res = $self->ua->request($req);

    my $content_type = $res->header('Content-Type');
    if ($content_type ne 'application/json' && $content_type ne 'application/x-www-form-urlencoded') {
        die "Not Supported Content-Type";
    }

    if ($content_type eq 'application/json') {
        $data = decode_json($res->content);
    } else {
        my $content = $res->decoded_content;
        my @params = split('&', $content);
        for my $param (@params) {
            my ($key, $value) = split /=/, $param;
            $data->{$key} = $value;
        }
    }

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
            $self->expires_in($dt);
        }
    }

    return ($res->is_success, $data);
}

sub _refresh_token { shift->token('RT') }

__PACKAGE__->meta->make_immutable;

1;
