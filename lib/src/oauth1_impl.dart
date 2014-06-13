// Copyright (c) 2014 popkirby <popkirby@gmail.com>
// This software is released under the MIT License, see LICENSE.txt.

part of oauth1;

class _OAuth1 implements OAuth1 {
  Map<String, String> _parameters;
  String consumerSecret;
  String tokenSecret;
  String method;
  Uri uri;


  String get consumerKey => _parameters[OAuth1.OAUTH_CONSUMER_KEY];

  set consumerKey(String value) => _parameters[OAuth1.OAUTH_CONSUMER_KEY] = value;

  String get token => _parameters[OAuth1.OAUTH_TOKEN];

  set token(String value) => _parameters[OAuth1.OAUTH_TOKEN];

  String get timestamp => _parameters[OAuth1.OAUTH_TIMESTAMP];

  String get nonce => _parameters[OAuth1.OAUTH_NONCE];

  Map<String, String> get parameters => _parameters;

  OAuth1Header get header {
    _OAuth1Header h = new _OAuth1Header(method, uri, _parameters,
                                        consumerSecret, tokenSecret);
    h.sign();
    return h;
  }

  _OAuth1(this.method, uri, String consumerKey, this.consumerSecret,
          String token, this.tokenSecret)
      : _parameters = {} {

    String getNonce() {
      return new DateTime.now().millisecondsSinceEpoch.toString();
    }

    _parameters[OAuth1.OAUTH_CONSUMER_KEY] = consumerKey;
    if (token != null) _parameters[OAuth1.OAUTH_TOKEN] = token;
    _parameters[OAuth1.OAUTH_TIMESTAMP]
      = (new DateTime.now().millisecondsSinceEpoch ~/ 1000).toInt().toString();
    _parameters[OAuth1.OAUTH_NONCE] = getNonce();
    _parameters[OAuth1.OAUTH_SIGNATURE_METHOD] = 'HMAC-SHA1';
    _parameters[OAuth1.OAUTH_VERSION] = OAuth1.VERSION;

    if (uri is Uri) {
      this.uri = uri;
    } else {
      this.uri = Uri.parse(uri);
    }

  }

  void addParameter(String key, String value) {
    parameters[key] = value;
  }

  void addParameters(Map<String, String> params) => _parameters.addAll(params);

  void addParametersFromString(String params) {
    params.split('&').forEach((e) {
      var t = e.split('=');
      addParameter(t[0], t[1]);
    });
  }

}

class _OAuth1Header implements OAuth1Header {

  Map<String, String> _parameters;
  String _method;
  Uri _uri;
  String _consumerSecret;
  String _tokenSecret;

  Map<String, String> get parameters => _parameters;

  bool isSigned() {
    return (_parameters[OAuth1.OAUTH_SIGNATURE] != null);
  }

  String sign() {

    if (isSigned()) return _parameters[OAuth1.OAUTH_SIGNATURE];

    String getSignatureValue() {
      var sortedKeys = _parameters.keys.toList()..sort();
      var tmp = [];

      sortedKeys.forEach((key) => tmp.add('${key}=${_parameters[key]}'));

      return '${_method}&${Uri.encodeComponent(_uri.toString())}&'
             '${Uri.encodeComponent(tmp.join('&'))}';
    }

    var signatureKey = '${_consumerSecret}&${_tokenSecret}';

    var hmac_sha1 = new HMAC(new SHA1(), signatureKey.codeUnits);
    hmac_sha1.add(getSignatureValue().codeUnits);

    _parameters[OAuth1.OAUTH_SIGNATURE] = CryptoUtils.bytesToBase64(hmac_sha1.close());
    return _parameters[OAuth1.OAUTH_SIGNATURE];

  }

  _OAuth1Header(this._method, this._uri, this._parameters,
                this._consumerSecret, String tokenSecret) {
    if (tokenSecret == null) {
      _tokenSecret = '';
    } else {
      _tokenSecret = tokenSecret;
    }
  }

  String toString() {
    sign();
    var tmp = [];
    _parameters.forEach((k, v) => tmp.add('$k="${Uri.encodeComponent(v)}"'));
    return 'OAuth ${tmp.join(', ')}';
  }

}
