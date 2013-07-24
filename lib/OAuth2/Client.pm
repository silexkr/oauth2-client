package OAuth2::Client;

use Moose;
use DateTime;
use HTTP::Request;

with 'OAuth2::Traits::Client';

has [qw/client_id client_secret authorization_endpoint token_endpoint/] => (
    is  => 'ro',
    isa => 'Str'
);

has 'accept' => (
    is      => 'ro',
    isa     => 'Str',
    default => '',
);

has [qw/_access_token _token_type _refresh_token _scope/] => (
    is      => 'rw',
    isa     => 'Str',
    default => '',
);

has '_expires_in' => (
    is  => 'rw',
    isa => 'DateTime'
);

sub token {
    my ($self, $grant_type, %args) = @_;

    ### AC  : AuthorizationCode
    ### IM  : Implicit
    ### ROPC: ResourceOwnerPasswordCredentials
    ### CC  : ClientCredentials
    ### RT  : RefreshToken
    die "Unknown Grant-Type"
        unless grep { $grant_type eq $_ } qw/AC IMP ROPC CC RT/;

    my $req = HTTP::Request->new(GET => $self->token_endpoint);
    $req->header(Accept => $self->accept) if $self->accept;
    my %query_params;

    if ($grant_type =~ /^(R|C)/) {
        my $credentials = $self->basic_credentials($self->client_id, $self->client_secret);
        $req->header(Authorization => $credentials);
    }

    if ($grant_type =~ /^A/) {
        # GRANT_TYPE, CODE, REDIRECT_URI, CLIENT_ID
        %query_params = (
            client_id    => $self->client_id,
            code         => '', # NEED THIS
            grant_type   => 'authorization_code',
            redirect_uri => '', # AND THIS
        );
    } elsif ($grant_type =~ /^I/) {
    } elsif ($grant_type =~ /^ROOC$/) {
        # GRANT_TYPE, USERNAME, PASSWORD, scope
        my $grant_type_option = $self->grant_type_option;
        %query_params = (
            grant_type => 'password',
            username   => $grant_type_option->{username},
            password   => $grant_type_option->{password},
        );
        $query_params{scope} = $args{scope} if $args{scope};
    } elsif ($grant_type =~ /^C/) {
        # GRANT_TYPE, scope
        $query_params{grant_type} = 'client_credentials';
        $query_params{scope} = $args{scope} if $args{scope};
    } elsif ($grant_type =~ /^RT$/) {
        # GRANT_TYPE, REFRESH_TOKEN, scope

        die "refresh_token is required" unless $self->refresh_token;

        %query_params = (
            grant_type    => 'refresh_token',
            refresh_token => $self->refresh_token,
        );
        $query_params{scope} = $opt->{scope} if $opt->{scope};
    } else {
        die "Invalid Grant-Type";
    }

    $req->uri->query_form(%query_params);
    my $res = $self->ua->request($req);
    my $data;

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
        $self->_access_token($data->{access_token});
        $self->_token_type($data->{token_type});

        $self->_refresh_token($data->{refresh_token}) if $data->{refresh_token};
        $self->_scope($data->{scope})                 if $data->{scope};
        if (my $expires_in = $data->{expires_in}) {
            my $epoch = DateTime->now->epoch;
            my $dt    = DateTime->from_epoch(epoch => $epoch + $expires_in);
            $self->_expires_in($dt);
        }
    }

    return ($res->is_success, $data);
}

sub refresh_token { shift->token('RT') }
sub authorize {}

__PACKAGE__->meta->make_immutable;

1;
