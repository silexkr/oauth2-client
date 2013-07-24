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

my ($is_success, $data, $location);
($is_success, $data, $location) =
  $client->authorize(
      'code',
      redirect_uri => 'http://restore.e-crf.co.kr:5001/',
      state        => 'xyz'
  );

($is_success, $data) =
  $client->token(
      'AC',
      code         => $data->{code},
      redirect_uri => $location
  );

($is_success, $data) =
  $client->token(
      'ROPC',
      username => 'aanoaa',
      password => '123456'
  );

done_testing();
