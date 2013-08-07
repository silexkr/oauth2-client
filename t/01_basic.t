use Test::More;
use OAuth2::Client;
use URI;

my $client = OAuth2::Client->new(
    client_id              => '5c4b5f41-f0f2-4fdd-aa7a-b161b4ee04d7',
    client_secret          => 'cjsKzVX3bJw7FkZdT5BiIIc3',
    authorization_endpoint => 'http://auth.silex.kr:5000/oauth/authorize',
    token_endpoint         => 'http://auth.silex.kr:5000/oauth/token',
);

ok($client, 'Create an instance');

my ($req, $token);
$req = $client->authorization_request(
    response_type => 'code',
    redirect_uri  => 'http://restore.e-crf.co.kr:5001/',
    state         => 'xyz'
);

# diag($req->as_string);

$req = $client->token_request(
    grant_type   => 'Authorization Code',
    code         => 'aXW2c6bYz',
    redirect_uri => 'http://restore.e-crf.co.kr:5001/',
);

$req = $client->token_request(
    grant_type => 'Resource Owner Password Credentials',
    username   => 'aanoaa',
    password   => '123456'
);

# diag($req->as_string);
done_testing();
