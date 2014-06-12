// Copyright (c) 2014 popkirby <popkirby@gmail.com>
// This software is released under the MIT License, see LICENSE.txt.

part of oauth1;

/**
 * Simple OAuth 1.0a header generator.
 * Only supports HMAC-SHA1 signature method now.
 */
class OAuth1 {
  static const VERSION = '1.0';

  String consumerKey;
  String consumerSecret;
  String token;
  String tokenSecret;
  String method;
  Uri uri;
  Map<String, String> parameters;

  String _timestamp;
  String _nonce;


  OAuth1(this.method, dynamic uri, this.consumerKey, this.consumerSecret, [this.token = '', this.tokenSecret='']): parameters = {
  }, _timestamp = (new DateTime.now().millisecondsSinceEpoch ~/ 1000).toInt().toString() {

    if (uri is Uri) {
      this.uri = uri;
    } else {
      this.uri = Uri.parse(uri);
    }
    _nonce = _getNonce();
    _initAuthParams();
  }

  void addParameter(String key, String value) {
    parameters[key] = value;
  }

  void addParameters(Map<String, String> params) => parameters.addAll(params);

  void addParametersFromString(String params) {
    params.split('&').forEach((e) {
      var t = e.split('=');
      addParameter(t[0], t[1]);
    });
  }

  OAuth1Header get header {
    _OAuth1Header h = new _OAuth1Header(parameters);
    if (h.parameters['oauth_signature'] == null) h.parameters['oauth_signature'] = signature;
    return h;
  }

  String get signature {
    var hmac_sha1 = new HMAC(new SHA1(), _signatureKey.codeUnits);
    hmac_sha1.add(_signatureValue.codeUnits);
    return CryptoUtils.bytesToBase64(hmac_sha1.close());
  }

  String get _signatureKey => '${consumerSecret}&${tokenSecret}';

  String get _signatureValue {
    var sortedKeys = parameters.keys.toList()
      ..sort();
    var tmp = [];

    sortedKeys.forEach((key) => tmp.add('${key}=${parameters[key]}'));

    return '${method}&${Uri.encodeComponent(uri.toString())}&${Uri.encodeComponent(tmp.join('&'))}';
  }

  void _initAuthParams() {
    parameters = {
      'oauth_consumer_key': consumerKey, 'oauth_timestamp': _timestamp, 'oauth_nonce': _nonce, 'oauth_signature_method': 'HMAC-SHA1', 'oauth_version': OAuth1.VERSION
    };

    if (token != '') parameters['oauth_token'] = token;
  }
}

abstract class OAuth1Header {
  Map<String, String> parameters;

  OAuth1Header(this.parameters);

  String toString();
}

String _getNonce() {
  var sha1 = new SHA1();
  sha1.add(new DateTime.now().millisecondsSinceEpoch.toString().codeUnits);
  return new String.fromCharCodes(sha1.close());
}
