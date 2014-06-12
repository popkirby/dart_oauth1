// Copyright (c) 2014 popkirby <popkirby@gmail.com>
// This software is released under the MIT License, see LICENSE.txt.

part of oauth1;

class _OAuth1Header implements OAuth1Header {
  Map<String, String> parameters;

  _OAuth1Header(this.parameters);

  String toString() {
    var tmp = [];
    parameters.forEach((k, v) => tmp.add('$k="${Uri.encodeComponent(v)}"'));
    return 'OAuth ${tmp.join(', ')}';
  }

}