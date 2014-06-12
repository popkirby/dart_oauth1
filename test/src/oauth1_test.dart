// Copyright (c) 2014 popkirby <popkirby@gmail.com>
// This software is released under the MIT License, see LICENSE.txt.

part of oauth1_test;

void oauth1_test() {
  test('valid signature', () {
    var oauth1 = new OAuth1('GET', 'http://example.com/test', 'consumerkey', 'consumersecret');
    oauth1.addParameters({
      'oauth_timestamp': '1000',
      'oauth_nonce': '2000'
    });

    oauth1.addParametersFromString('param1=value1&param2=value2');

    expect(oauth1.signature, equals('PiiQpOG0uyWFKgCnXxeDGFMGMqc='));
  });

  test('header must returns same value', () {
    var oauth1 = new OAuth1('GET', 'http://example.com/test', 'consumerkey', 'consumersecret');

    expect(oauth1.header.toString(), equals(oauth1.header.toString()));
  });
}

