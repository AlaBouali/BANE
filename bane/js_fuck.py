"""
P.S: I didn't write the following class but i find it very useful to encode XSS payloads. I would like to thank the guy who did it, good job bro <3
"""
class js_fuck(object):
    '''
    Encodes/Decodes Javascript using JSFuck 0.4.0
    (https://github.com/aemkei/jsfuck)

    Class variables:
    USE_CHAR_CODE   -- string used to indicate which keys in MAPPING will
                                           be encoded using their ASCII character code

    MIN                            -- int the position within MAPPING dictionary to start
                                          iterating from, for the final encoding pass

    MAX                          -- int the maximum value to iterate in MAPPING
                                         on the final encode

    SIMPLE                    -- dictionary of built-in Javascript types and values

    CONSTRUCTORS   -- dictionary of mostly Javascript data types

    MAPPING                -- dictionary of every character to be mapped and decoded

    GLOBAL                  -- string used to replace 'GLOBAL' value on final encode

    '''

    USE_CHAR_CODE = "USE_CHAR_CODE"

    MIN, MAX = 32, 126

    SIMPLE = {
        'false':      '![]',
        'true':       '!![]',
        'undefined':  '[][[]]',
        'NaN':        '+[![]]',
        'Infinity':   ('+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+'
                       '!+[]]+[+[]]+[+[]]+[+[]])')  # +"1e1000"
    }

    CONSTRUCTORS = {
        'Array':    '[]',
        'Number':   '(+[])',
        'String':   '([]+[])',
        'Boolean':  '(![])',
        'Function': '[]["fill"]',
        'RegExp':   'Function("return/"+false+"/")()'
    }

    MAPPING = {
        'a':   '(false+"")[1]',
        'b':   '([]["entries"]()+"")[2]',
        'c':   '([]["fill"]+"")[3]',
        'd':   '(undefined+"")[2]',
        'e':   '(true+"")[3]',
        'f':   '(false+"")[0]',
        'g':   '(false+[0]+String)[20]',
        'h':   '(+(101))["to"+String["name"]](21)[1]',
        'i':   '([false]+undefined)[10]',
        'j':   '([]["entries"]()+"")[3]',
        'k':   '(+(20))["to"+String["name"]](21)',
        'l':   '(false+"")[2]',
        'm':   '(Number+"")[11]',
        'n':   '(undefined+"")[1]',
        'o':   '(true+[]["fill"])[10]',
        'p':   '(+(211))["to"+String["name"]](31)[1]',
        'q':   '(+(212))["to"+String["name"]](31)[1]',
        'r':   '(true+"")[1]',
        's':   '(false+"")[3]',
        't':   '(true+"")[0]',
        'u':   '(undefined+"")[0]',
        'v':   '(+(31))["to"+String["name"]](32)',
        'w':   '(+(32))["to"+String["name"]](33)',
        'x':   '(+(101))["to"+String["name"]](34)[1]',
        'y':   '(NaN+[Infinity])[10]',
        'z':   '(+(35))["to"+String["name"]](36)',

        'A':   '(+[]+Array)[10]',
        'B':   '(+[]+Boolean)[10]',
        'C':   'Function("return escape")()(("")["italics"]())[2]',
        'D':   'Function("return escape")()([]["fill"])["slice"]("-1")',
        'E':   '(RegExp+"")[12]',
        'F':   '(+[]+Function)[10]',
        'G':   '(false+Function("return Date")()())[30]',
        'H':   USE_CHAR_CODE,
        'I':   '(Infinity+"")[0]',
        'J':   USE_CHAR_CODE,
        'K':   USE_CHAR_CODE,
        'L':   USE_CHAR_CODE,
        'M':   '(true+Function("return Date")()())[30]',
        'N':   '(NaN+"")[0]',
        'O':   '(NaN+Function("return{}")())[11]',
        'P':   USE_CHAR_CODE,
        'Q':   USE_CHAR_CODE,
        'R':   '(+[]+RegExp)[10]',
        'S':   '(+[]+String)[10]',
        'T':   '(NaN+Function("return Date")()())[30]',
        'U':   ('(NaN+Function("return{}")()["to"+String'
                '["name"]]["call"]())[11]'),
        'V':   USE_CHAR_CODE,
        'W':   USE_CHAR_CODE,
        'X':   USE_CHAR_CODE,
        'Y':   USE_CHAR_CODE,
        'Z':   USE_CHAR_CODE,

        ' ':   '(NaN+[]["fill"])[11]',
        '!':   USE_CHAR_CODE,
        '"':   '("")["fontcolor"]()[12]',
        '#':   USE_CHAR_CODE,
        '$':   USE_CHAR_CODE,
        '%':   'Function("return escape")()([]["fill"])[21]',
        '&':   '("")["link"](0+")[10]',
        '\'':  USE_CHAR_CODE,
        '(':   '(undefined+[]["fill"])[22]',
        ')':   '([0]+false+[]["fill"])[20]',
        '*':   USE_CHAR_CODE,
        '+':   ('(+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]'
                '+[+!+[]]+[+[]]+[+[]])+[])[2]'),
        ',':   '([]["slice"]["call"](false+"")+"")[1]',
        '-':   '(+(.+[0000000001])+"")[2]',
        '.':   ('(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+'
                '[]+!+[]]+[+[]])+[])[+!+[]]'),
        '/':   '(false+[0])["italics"]()[10]',
        ':':   '(RegExp()+"")[3]',
        ';':   '("")["link"](")[14]',
        '<':   '("")["italics"]()[0]',
        '=':   '("")["fontcolor"]()[11]',
        '>':   '("")["italics"]()[2]',
        '?':   '(RegExp()+"")[2]',
        '@':   USE_CHAR_CODE,
        '[':   '([]["entries"]()+"")[0]',
        '\\':  USE_CHAR_CODE,
        ']':   '([]["entries"]()+"")[22]',
        '^':   USE_CHAR_CODE,
        '_':   USE_CHAR_CODE,
        '`':   USE_CHAR_CODE,
        '{':   '(true+[]["fill"])[20]',
        '|':   USE_CHAR_CODE,
        '}':   '([]["fill"]+"")["slice"]("-1")',
        '~':   USE_CHAR_CODE
    }

    GLOBAL = 'Function("return this")()'

    def __init__(self, js=None):
        '''
        Checks if passed some Javascript and if so assigns an instance variable
        to that of the pass Javascript.

        Populates MAPPING dictionary with the keys corresponding encoded value.

        Keyword arguments:
        js -- string containing the encoded Javascript to be
              decoded (defualt None)

        '''
        if js:
            self.js = js

        self.__fillMissingDigits()
        self.__fillMissingChars()
        self.__replaceMap()
        self.__replaceStrings()

    def decode(self, js=None):
        '''
        Decodes JSFuck'd Javascript

        Keyword arguments:
        js -- string containing the JSFuck to be decoded (defualt None)

        Returns:
        js -- string of decoded Javascript

        '''
        if not js:
            js = self.js

        js = self.__mapping(js)

        # removes concatenation operators
        js = re.sub('\+(?!\+)', '', js)
        js = js.replace('++', '+')

        # check to see if source js is eval'd
        if '[][fill][constructor]' in js:
            js = self.uneval(js)

        self.js = js

        return js

    def encode(self, js=None, wrapWithEval=False, runInParentScope=False):
        '''
        Encodes vanilla Javascript to JSFuck obfuscated Javascript

        Keyword arguments:
        js                            -- string of unobfuscated Javascript

        wrapWithEval        -- boolean determines whether to wrap with an eval

        runInParentScope -- boolean determines whether to run in parents scope

        '''
        output = []

        if not js:
            js = self.js

            if not js:
                return ''

        regex = ''

        for i in self.SIMPLE:
            regex += i + '|'

        regex += '.'

        def inputReplacer(c):
            c = c.group()
            replacement = self.SIMPLE[c] if c in self.SIMPLE else False

            if replacement:
                output.append('[' + replacement + ']+[]')

            else:
                replacement = self.MAPPING[c] if c in self.MAPPING else False

                if replacement:
                    output.append(replacement)
                else:
                    replacement = (
                        '([]+[])[' + self.encode('constructor') + ']'
                        '[' + self.encode('fromCharCode') + ']'
                        '(' + self.encode(str(ord(c[0]))) + ')')

                    output.append(replacement)
                    self.MAPPING[c] = replacement

        re.sub(regex, inputReplacer, js)

        output = '+'.join(output)

        if re.search(r'^\d$', js):
            output += "+[]"

        if wrapWithEval:
            if runInParentScope:
                output = ('[][' + self.encode('fill') + ']'
                          '[' + self.encode('constructor') + ']'
                          '(' + self.encode('return eval') + ')()'
                          '(' + output + ')')

            else:
                output = ('[][' + self.encode('fill') + ']'
                          '[' + self.encode('constructor') + ']'
                          '(' + output + ')')

        self.js = output

        return output

    def uneval(self, js):
        '''
        Unevals a piece of Javascript wrapped with an encoded eval

        Keyword arguments:
        js -- string containing an eval wrapped string of Javascript

        Returns:
        js -- string with eval removed

        '''
        js = js.replace('[][fill][constructor](', '')
        js = js[:-2]

        ev = 'return eval)()('

        if ev in js:
            js = js[(js.find(ev) + len(ev)):]

        return js

    def __mapping(self, js):
        '''
        Iterates over MAPPING and replaces every value found with
        its corresponding key

        Keyword arguments:
        js -- string containing Javascript encoded with JSFuck

        Returns:
        js -- string of decoded Javascript

        '''
        for key, value in sorted(
                self.MAPPING.items(), key=lambda x: len(x[1]), reverse=True):
            js = js.replace(value, key)

        return js

    def __fillMissingDigits(self):
        '''
        Calculates 0-9's encoded value and adds it to MAPPING

        '''
        for number in xrange(10):
            output = '+[]'

            if number > 0:
                output = '+!' + output

            for i in xrange(number - 1):
                output = '+!+[]' + output

            if number > 1:
                output = output[1:]

            self.MAPPING[str(number)] = '[' + output + ']'

    def __fillMissingChars(self):
        '''
        Iterates over MAPPING and fills missing character values with a string
        containing their ascii value represented in hex

        '''
        for key in self.MAPPING:
            if self.MAPPING[key] == self.USE_CHAR_CODE:
                hexidec = hex(ord(key[0]))[2:]

                digit_search = re.findall(r'\d+', hexidec)
                letter_search = re.findall(r'[^\d+]', hexidec)

                digit = digit_search[0] if digit_search else ''
                letter = letter_search[0] if letter_search else ''

                string = ('Function("return unescape")()("%%"+(%s)+"%s")'
                          % (digit, letter))

                self.MAPPING[key] = string

    def __replaceMap(self):
        '''
        Iterates over MAPPING from MIN to MAX and replaces value with values
        found in CONSTRUCTORS and SIMPLE, as well as using digitalReplacer and
        numberReplacer to replace numeric values

        '''
        def replace(pattern, replacement):
            return re.sub(pattern, replacement, value, flags=re.I)

        def digitReplacer(x):
            return self.MAPPING[x.group(1)]

        def numberReplacer(y):
            values = list(y.group(1))
            head = int(values[0])
            output = '+[]'

            values.pop(0)

            if head > 0:
                output = '+!' + output

            for i in xrange(1, head):
                output = '+!+[]' + output

            if head > 1:
                output = output[1:]

            return re.sub(r'(\d)', digitReplacer, '+'.join([output] + values))

        for i in xrange(self.MIN, self.MAX + 1):
            character = chr(i)
            value = self.MAPPING[character]

            original = ''

            if not value:
                continue

            while value != original:
                original = value

                for key, val in self.CONSTRUCTORS.iteritems():
                    value = replace(r'\b' + key, val + '["constructor"]')

                for key, val in self.SIMPLE.iteritems():
                    value = replace(key, val)

            value = replace(r'(\d\d+)', numberReplacer)
            value = replace(r'\((\d)\)', digitReplacer)
            value = replace(r'\[(\d)\]', digitReplacer)

            value = replace(r'GLOBAL', self.GLOBAL)
            value = replace(r'\+""', '+[]')
            value = replace(r'""', '[]+[]')

            self.MAPPING[character] = value

    def __replaceStrings(self):
        '''
        Replaces strings added in __replaceMap with there encoded values

        '''
        regex = r'[^\[\]\(\)\!\+]'

        # determines if there are still characters to replace
        def findMissing():
            done = False
            # python 2 workaround for nonlocal
            findMissing.missing = {}

            for key, value in self.MAPPING.iteritems():
                if re.findall(regex, value):
                    findMissing.missing[key] = value
                    done = True

            return done

        def mappingReplacer(x):
            return '+'.join(list(x.group(1)))

        def valueReplacer(x):
            x = x.group()
            return x if x in findMissing.missing else self.MAPPING[x]

        for key in self.MAPPING:
            self.MAPPING[key] = re.sub(r'\"([^\"]+)\"', mappingReplacer,
                                       self.MAPPING[key], flags=re.I)

        while findMissing():
            for key in findMissing.missing:
                value = self.MAPPING[key]
                value = re.sub(regex, valueReplacer, value)

                self.MAPPING[key] = value
                findMissing.missing[key] = value

