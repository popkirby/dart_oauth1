// Copyright (c) 2014 popkirby <popkirby@gmail.com>
// This software is released under the MIT License, see LICENSE.txt.

part of oauth1;

/**
 * Simple OAuth 1.0a header generator.
 * Only supports HMAC-SHA1 signature method now.
 */
abstract class OAuth1 {
  /**
   * version of OAuth, now only 1.0.
   */
  static const VERSION = '1.0';

  static const OAUTH_CONSUMER_KEY = 'oauth_consumer_key';
  static const OAUTH_TOKEN = 'oauth_token';
  static const OAUTH_TIMESTAMP = 'oauth_timestamp';
  static const OAUTH_NONCE = 'oauth_nonce';
  static const OAUTH_SIGNATURE_METHOD = 'oauth_signature_method';
  static const OAUTH_VERSION = 'oauth_version';
  static const OAUTH_SIGNATURE = 'oauth_signature';

  /**
   * Gets and sets the consumer key. The value of this property will reflect
   * 'oauth_consumer_key' value of OAuth header.
   */
  String consumerKey;

  /**
   * Gets and sets the consumer secret key. The value of this property will be
   * used in signature method.
   */
  String consumerSecret;

  /**
   * Gets and sets the oauth token. The value of this property will be reflect
   * 'oauth_token' value of OAuth header.
   */
  String token;

  /**
   * Gets and sets the oauth token secret. The value of this property will be
   * used in signature method.
   */
  String tokenSecret;

  /**
   * Gets the timestamp.
   */
  String get timestamp;

  /**
   * Gets the nonce.
   */
  String get nonce;

  /**
   * Gets and sets the method for connection.
   */
  String method;

  /**
   * Gets and sets the URI to connect.
   */
  Uri uri;

  /**
   * Gets parameters for OAuth connection.
   */
  Map<String, String> get parameters;

  /**
   * Gets the [OAuth1Header] instance for OAuth connection.
   * The value will be used in 'Authorization' header.
   */
  OAuth1Header get header;

  factory OAuth1(String method, uri, String consumerKey, String consumerSecret, [String token, String tokenSecret]) {
    return new _OAuth1(method, uri, consumerKey, consumerSecret, token, tokenSecret);
  }

  /**
   * Add a parameter for OAuth connection.
   */
  void addParameter(String key, String value);

  /**
   * Add some parameters for OAuth connection from a Map.
   */
  void addParameters(Map<String, String> params);

  /**
   * Add some parameters for OAuth connection from a string.
   * The string should be like 'param1=value1&param2=value2'.
   */
  void addParametersFromString(String params);

}

/**
 * Header class for OAuth connection.
 */
abstract class OAuth1Header {

  /**
   * Gets the parameters for OAuth connection.
   */
  Map<String, String> get parameters;

  /**
   * Returns if the header is signed or not.
   */
  bool isSigned();

  /**
   * Sign the header and returns signature string.
   * If the instance is already signed, this immidiately returns signature string.
   */
  String sign();

  /**
   * Returns OAuth authentication string, which will be used in
   * 'Authorization' header.
   * The value is like 'OAuth param1=value1&oauth_timestamp=...&oauth_...'
   */
  String toString();

  /**
   * Construct header.
   */
  OAuth1Header(String method, Uri uri, Map<String, String> parameters,
               String consumerSecret, String tokenSecret);

}
