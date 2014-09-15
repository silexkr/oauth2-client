use strict;
use warnings;

use Test::More;

use Time::Piece;

use OAuth2::Client::Password;

my $username = $ENV{TEST_NET_SILEX_USERNAME};
my $password = $ENV{TEST_NET_SILEX_PASSWORD};

SKIP: {
    skip "ENV - TEST_NET_SILEX_USERNAME, TEST_NET_SILEX_PASSWORD is required",
        9
        unless $username && $password;

    my $client = OAuth2::Client::Password->new(
        uri           => 'https://auth.silex.kr/oauth/token',
        username      => 'aanoaa',
        password      => '123456',
        client_id     => 'afc761ce-c153-40f5-9796-d2f0ddb41b5d',
        client_secret => 'nWo1fXg94qiN2yf5rToq1TQL',
    );

    ok $client, 'client object';

#
# access token
#
    {
        ok $client->auth, 'auth()';

        {
            my $got      = $client->scope;
            my $expected = '';
            is $got, $expected, 'access token - scope';
        }

        {
            my $got      = $client->token_type;
            my $expected = 'Bearer';
            is $got, $expected, 'access token - token_type';
        }

        {
            my $got      = $client->expires;
            my $expected = gmtime->epoch + 31536000;
            is $got, $expected, 'access token - expires';
        }
    }

#
# refresh token
#
    {
        ok $client->refresh, 'refresh()';

        {
            my $got      = $client->scope;
            my $expected = '';
            is $got, $expected, 'refresh token - scope';
        }

        {
            my $got      = $client->token_type;
            my $expected = 'Bearer';
            is $got, $expected, 'refresh token - token_type';
        }

        {
            my $got      = $client->expires;
            my $expected = gmtime->epoch + 31536000;
            is $got, $expected, 'refresh token - expires';
        }
    }
}

done_testing;
