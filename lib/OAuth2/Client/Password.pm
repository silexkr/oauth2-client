package OAuth2::Client::Password;

# ABSTRACT: OAuth2 client - password
# VERSION

use OAuth2::Client;

use Moo;
use Types::Standard qw( Int Str );
use namespace::clean -except => 'meta';

use HTTP::Tiny;
use JSON;
use MIME::Base64 qw( encode_base64 );
use Time::Piece;
use Try::Tiny;

has uri           => ( is => 'ro', isa => Str, required => 1 );
has username      => ( is => 'ro', isa => Str, required => 1 );
has password      => ( is => 'ro', isa => Str, required => 1 );
has client_id     => ( is => 'ro', isa => Str, required => 1 );
has client_secret => ( is => 'ro', isa => Str, required => 1 );

has scope         => ( is => 'rw', isa => Str, clearer => 1 );
has access_token  => ( is => 'rw', isa => Str, clearer => 1 );
has refresh_token => ( is => 'rw', isa => Str, clearer => 1 );
has token_type    => ( is => 'rw', isa => Str, clearer => 1 );
has expires       => ( is => 'rw', isa => Int, clearer => 1 );

has agent => (
    is      => 'rw',
    isa     => Str,
    default => "OAuth2-Client-Password/$OAuth2::Client::VERSION",
);

sub auth    { $_[0]->_get_access_token }
sub refresh { $_[0]->_get_access_token('refresh') }

sub _get_access_token {
    my ( $self, $type ) = @_;

    my %params;
    $params{scope} = $self->scope if defined $self->scope;
    if ( !$type ) {
        $self->_clear, return
            unless defined $self->username && defined $self->password;

        %params = (
            grant_type => 'password',
            username   => $self->username,
            password   => $self->password,
        );
    }
    elsif ( $type eq 'refresh' ) {
        $self->_clear, return unless defined $self->refresh_token;

        %params = (
            grant_type    => 'refresh_token',
            refresh_token => $self->refresh_token,
        );
    }

    my $http = HTTP::Tiny->new(
        agent           => $self->agent,
        default_headers => {
            authorization => sprintf(
                'Basic %s',
                encode_base64(
                    $self->client_id . ':' . $self->client_secret, q{},
                ),
            ),
        },
    );

    my $res = $http->post_form( $self->uri, \%params );

    $self->_clear, return unless $res->{success};
    $self->_clear, return
        unless $res->{headers}{'content-type'} eq 'application/json';

    my $data = try { decode_json( $res->{content} ) };
    $self->_clear, return unless $data;

    $self->_clear, return unless defined $data->{access_token};
    $self->access_token( $data->{access_token} );

    $self->_clear, return unless defined $data->{token_type};
    $self->token_type( $data->{token_type} );

    $self->refresh_token( $data->{refresh_token} )
        if defined $data->{refresh_token};
    $self->expires( gmtime->epoch + $data->{expires_in} )
        if defined $data->{expires_in};

    # http://tools.ietf.org/html/rfc6749#section-3.3
    $self->scope( $data->{scope} // '' );

    return 1;
}

sub _clear {
    my $self = shift;

    $self->clear_scope;
    $self->clear_access_token;
    $self->clear_refresh_token;
    $self->clear_token_type;
    $self->clear_expires;
}

1;
__END__

=head1 SYNOPSIS

    use OAuth2::Client::Password;

    my $client = OAuth2::Client::Password->new(
        uri           => 'http://auth.silex.kr/oauth/token',
        username      => 'aanoaa',
        password      => '123456',
        client_id     => 'afc761ce-c153-40f5-9796-d2f0ddb41b5d',
        client_secret => 'nWo1fXg94qiN2yf5rToq1TQL',
    );

    $client->auth;

    say $client->scope;
    say $client->access_token;
    say $client->refresh_token;
    say $client->token_type;
    say $client->expires;

    $client->refresh;

    say $client->scope;
    say $client->access_token;
    say $client->refresh_token;
    say $client->token_type;
    say $client->expires;


=head1 DESCRIPTION

...


=attr uri

=attr username

=attr password

=attr client_id

=attr client_secret

=attr scope

=attr access_token

=attr refresh_token

=attr token_type

=attr expires

=attr agent


=method auth

=method refresh


=head1 SEE ALSO

=for :list
* https://github.com/silexkr/oauth2-client
* https://github.com/silexkr/auth-silex-kr
* https://github.com/silexkr/net-silex
