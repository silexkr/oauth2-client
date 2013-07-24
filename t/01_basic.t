use Test::More;
use OAuth2::Client;
use URI;

my $client = OAuth2::Client->new(
    client_id              => '5c4b5f41-f0f2-4fdd-aa7a-b161b4ee04d7',
    client_secret          => 'q76UgVkXi1VE50Ettc1TY2kMpgoJmqzWmCmy',
    authorization_endpoint => 'http://auth.silex.kr:5000/oauth/authorize',
    token_endpoint         => 'http://auth.silex.kr:5000/oauth/token',
    accept                 => 'application/json',
);

ok($client, 'Create an instance');

my ($is_success, $data);
($is_success, $data) = $client->token('ROPC', username => 'aanoaa', password => '123456');
($is_success, $data) = $client->token('RT');
done_testing();
