#!/usr/bin/python -tt
# vim: fileencoding=utf8
#{{{ License header: MIT
# Copyright (c) 2016 Till Maas <opensource@till.name>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#}}}

# Helper classes to manage burp config

protocols = dict(ANY=u"0", HTTP=u"1", HTTPS=u"2")


class ScopeEntry(object):
    def __init__(self, host=None, enabled=True, data=None):
        if host is not None:
            self.protocol = protocols["ANY"]
            self.enabled = enabled
            self.host = host
            self.remainder = u"0."
        elif data is not None:
            fields = data.split(".", 3)
            self.enabled = fields[0] == u"1"
            self.protocol = fields[1]
            hostlength = int(fields[2])
            self.host = fields[3][:hostlength]
            self.remainder = fields[3][hostlength:]
        else:
            raise RuntimeError("Data or host missing")

    def encode(self):
        res = u""
        if self.enabled:
            res += u"1"
        else:
            res += u"0"
        res += u"."

        res += self.protocol
        res += u"."
        res += unicode(len(self.host))
        res += u"."
        res += self.host
        res += self.remainder
        return res


class ScopeList(object):
    def __init__(self, prefix=u"target.droprequestsscope"):
        self.include = []
        self.exclude = []
        self.prefix = prefix

    def exclude_host(self, host):
        return self.append_host(self.exclude, host)

    def include_host(self, host):
        return self.append_host(self.include, host)

    def append_host(self, list_, host):
        if host not in [e.host for e in list_]:
            list_.append(ScopeEntry(host))

    def parse(self, config):
        remaining_config = {}
        for key, value in config.iteritems():
            if key.startswith(self.prefix):
                # note: len("exclude") == len("include")
                list_ = key[len(self.prefix):len(self.prefix + "exclude")]
                if list_ in ("exclude", "include"):
                    # set by burp for initial settings
                    if value != u"**empty**":
                        entry = ScopeEntry(data=value)
                        getattr(self, list_).append(entry)
                    continue

            else:
                remaining_config[key] = value
        return remaining_config

    def encode(self):
        res = {}
        for list_ in "exclude", "include":
            res.update(self.encode_list(list_))
        return res

    def encode_list(self, what):
        res = {}
        prefix = self.prefix + what
        list_ = getattr(self, what)
        for number, item in enumerate(list_):
            key = prefix + unicode(number)
            value = item.encode()
            res[key] = value
        return res

if __name__ == "__main__":
    import pprint
    sl = ScopeList()
    for i in range(30):
        sl.include_host("www" + str(i) + ".example.com")
    encodeda = sl.encode()
    pprint.pprint(encodeda)
    sl = ScopeList()
    sl.parse(encodeda)
    encoded = sl.encode()
    pprint.pprint(encoded)
