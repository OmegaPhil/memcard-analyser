#!/usr/bin/env python3

'''
Version 0.01 2013.03.04
Copyright (c) 2013, OmegaPhil - OmegaPhil+memcard-analyser@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

GPL_NOTICE = '''
Copyright (C) 2013 OmegaPhil
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
'''

import io
import os.path
import string
import sys
import unicodedata

from optparse import OptionParser


# Format information and program structure based on dexux - see
# https://sourceforge.net/projects/dexux/ , more save information from
# http://www.ps3devwiki.com/wiki/Game_Saves#Memory_card_PS1_.28original.29

# TODO: A lot of progression has been obtained here - I need to write it up

# Initialising variables
VERSION = '0.01'  # Remember version in copyright notice

# Image format
IMAGE_SIZE = 131072
GME_MAGIC = b'123-456-STD'
GME_HEADER_SIZE = 3904
MCD_MAGIC = b'MC'
MCD_HEADER_SIZE = 0

# Memory card data structure
BLOCK_0_MAGIC_START = b'MC'
BLOCK_0_MAGIC = BLOCK_0_MAGIC_START + (b'\x00' * 125)
BLOCK_0_XOR = BLOCK_0_MAGIC_START[0] ^ BLOCK_0_MAGIC_START[1]
BLOCK_NORMAL_MAGIC = b'SC'
FRAME_SIZE = 128
FRAMES_IN_BLOCK = 64
BLOCK_SIZE = FRAME_SIZE * FRAMES_IN_BLOCK
BLOCK_STATUS = {0x51: 'First block',   # Integers need to be used as a single
                0x52: 'Middle block',  # byte indexed is an integer
                0x53: 'Last block',
                0xA0: 'Unused block',
                0xA1: 'Deleted block',
                0xFF: 'Unusable block'}
BLOCK_VALID_INFORMATION = {0xA0: False,  # Used to determine whether a
                0xA1: True,  # particular block's data should be reported on
                0x51: True,
                0x52: False,
                0x53: False,
                0xFF: False}
SAVE_LENGTH = {b'\x00\x20\x00': '1 block',
               b'\x00\x40\x00': '2 blocks',
               b'\x00\x60\x00': '3 blocks',
               b'\x00\x80\x00': '4 blocks',
               b'\x00\xA0\x00': '5 blocks',
               b'\x00\xC0\x00': '6 blocks',
               b'\x00\xE0\x00': '7 blocks',
               b'\x00\x00\x01': '8 blocks',
               b'\x00\x20\x01': '9 blocks',
               b'\x00\x40\x01': '10 blocks',
               b'\x00\x60\x01': '11 blocks',
               b'\x00\x80\x01': '12 blocks',
               b'\x00\xA0\x01': '13 blocks',
               b'\x00\xC0\x01': '14 blocks',
               b'\x00\xE0\x01': '15 blocks'}
COUNTRY_CODE = {b'BI': 'Japan',  # Road Rash has saves which use the lower
                b'bi': 'Japan',  # case country code...
                 b'BA': 'America',
                 b'ba': 'America',
                 b'BE': 'Europe',
                 b'be': 'Europe'}

# Creating a translation table to map non-printables to full stop
# (periods for Americans). Specifically ignoring whitespace here
# The 'in string.printable' is used as a test to then index the first
# list resulting in the appropriate replacement characters
# Credit: http://stackoverflow.com/a/1800889
# I have moved from Python 2 to 3 finally due to bullshit with this
# translationTable and how it is used. With the unicode_literals
# future import, the string literals used here result in this variable
# being unicode - this should be irrelevant as the whole point is to
# replace out all but the boring normal ASCII characters with '.'.
# However, as soon as translationTable is used in the translate
# method, you get a UnicodeDecodeError complaining about trying to
# interpret the data as ASCII. Fail!
# In Python 3, this table is used with bytes data and therefore due to
# stubbornness it must be encoded via ASCII to bytes...
translationTable = bytes(''.join([['.', chr(x)][chr(x) in string.printable]
                            for x in range(256)]), 'ascii')

class PS1Card(object):
    '''Representation of memory card, also maintaining the original data'''

    def __init__(self, cardPath):

        # Initialising variables
        self.format = 'unknown'
        self.path = cardPath
        self.image = None
        self._blocks = [None for i in range(16)]  # Store for instantiated
                                                  # memory card blocks - 0 is
                                                  # 'padding'

        # Validating passed card path
        if not os.path.isfile(cardPath):
            raise Exception('The passed memory card \'%s\' does not exist' %
                            cardPath)

        # Verbose output
        if options.verbose:
            print('Loading memory card image...')

        # Loading memory card image
        with io.open(cardPath, "rb") as cardImage:
            self.image = cardImage.read()

        # Verbose output
        if options.verbose:
            print('Memory card image loaded')

        # Determining format of image (and therefore validating it)
        self.determine_format_and_validate()

        # Parsing card
        self.parse()

    def __getitem__(self, blockNumber):
        '''Intercepting indexing operations to allow blocks to be
        referenced'''

        # Making sure the index is in an appropriate range
        if not (blockNumber >= 1 and blockNumber <= 15):
            raise Exception('Invalid memory card block number requested: %s'
                            % blockNumber)

        # Making sure the block has been instantiated
        if self._blocks[blockNumber] == None:
            raise Exception('Memory card block %s requested before '
                            'instantiation' % blockNumber)

        # Returning requested block
        return self._blocks[blockNumber]

    def __setitem__(self, blockNumber, block):
        '''Intercepting indexing operations to allow blocks to be
        saved'''

        # Making sure the index is in an appropriate range
        if not (blockNumber >= 1 and blockNumber <= 15):
            raise Exception('Invalid memory card block number requested: %s'
                            % blockNumber)

        # Making sure a block has actually been passed
        if not isinstance(block, PS1CardBlock):
            raise Exception('Attempt to save an invalid memory card block to '
                            'block number %s:\n\n%s' % (blockNumber, block))

        # Saving block in local store
        self._blocks[blockNumber] = block

    def determine_format_and_validate(self):
        '''Determines format of the loaded binary data and does basic
        validation'''

        # Determining format and correct image size
        if self.image[:11] == GME_MAGIC:
            self.format = 'gme'
            correctSize = IMAGE_SIZE + GME_HEADER_SIZE
        elif self.image[:2] == MCD_MAGIC:
            self.format = 'mcd'
            correctSize = IMAGE_SIZE
        else:

            # Format unknown - raising error
            self.format = 'unknown'
            raise Exception('The passed memory card \'%s\' is not a known '
                            'format' % self.path)

        # Basic validation
        if len(self.image) != correctSize:
            raise Exception('The passed memory card \'%s\' is a %s format '
                            'image, however it is %dB rather than %dB and '
                            'therefore corrupt' %
                            (self.path, self.format, len(self.image),
                             correctSize))

        # Verbose output
        if options.verbose:
            print('Image is %s format' % self.format)

    def extract(self, blockNumber, outputPath):
        '''Extract save data (minus headers) from block to given path'''

        # Verbose output
        if options.verbose:
            print('Extracting data from block %d to \'%s\'...' % (blockNumber,
                  outputPath))

        # Creating output directory if it doesn't exist
        if not os.path.isdir(os.path.dirname(outputPath)):
            os.makedirs(os.path.dirname(outputPath))

        # Setting offset at beginning of relevant block and determining the
        # next block
        offset = self.format_offset() + blockNumber * BLOCK_SIZE
        nextBlockOffset = offset + BLOCK_SIZE

        # This is the first block of a save, so skipping irrelevant headers
        # which are 4 frames long (title, icon etc)
        offset += 4 * FRAME_SIZE

        # Verbose output
        if options.verbose:
            print('Writing save data from memory card image byte %d to %d to '
                  '\'%s\'...' % (offset, nextBlockOffset - 1, outputPath))

        # Outputting save data to file
        with io.open(outputPath, 'wb') as outputFile:
            outputFile.write(self.image[offset:nextBlockOffset])

            # Looping for further blocks of a multiblock save
            i = 1
            while (self[blockNumber + i].blockStatus == 'Middle block' or
                    self[blockNumber + i].blockStatus == 'Last block' or
                    self[blockNumber + i].blockStatus == 'Deleted block'):

                # Calculating the next offsets - after the first block,
                # further blocks do not have headers
                offset = nextBlockOffset
                nextBlockOffset += BLOCK_SIZE

                # Writing data
                outputFile.write(self.image[offset:nextBlockOffset])

                # Looping for the next block
                i += 1

        # Verbose output
        if options.verbose:
            print('Data written')

    def format_offset(self):
        '''Returning the starting point of the memory card data based on the
        format'''

        if self.format == 'gme':
            return GME_HEADER_SIZE
        elif self.format == 'mcd':
            return MCD_HEADER_SIZE

    def list(self):
        '''List the contents of the memory card image'''

        # Looping for all blocks, skipping control block
        for block in self._blocks[1:]:
            print('\nBlock %(blockNumber)d:\nStatus: %(status)s\nTitle: \''
            '%(title)s\'\nSave length: %(saveLength)s\n'
            'Country code: %(countryCode)s\nProduct code: %(productCode)s\n'
            'Game playthrough identifier: %(gamePlayThroughIdentifier)s\n'
            '\'File name\': %(filename)s'
                  % {'blockNumber': block.blockNumber,
                     'status': block.blockStatus,
                     'title': block.title,
                     'saveLength': block.saveLength,
                     'countryCode': block.countryCode,
                     'productCode': block.productCode,
                     'gamePlayThroughIdentifier': block.gamePlayThroughIdentifier,
                     'filename': block.filename})

    def parse(self):
        '''Parse the card image - create object representation'''

        # Verbose output
        if options.verbose:
            print('Parsing memory card image...')

        # Fetching the offset to the first valid data
        offset = self.format_offset()

        # Fetching the header/metadata block, block 0
        if options.verbose:
            print('Parsing control block (block 0)...')
        controlBlock = self.image[offset:offset + BLOCK_SIZE]

        # Debug code
        #print(controlBlock[:len(BLOCK_0_MAGIC)])
        #print(controlBlock[FRAME_SIZE - 1])

        # Validating block 0
        if (controlBlock[:len(BLOCK_0_MAGIC)] != BLOCK_0_MAGIC or
            controlBlock[FRAME_SIZE - 1] != BLOCK_0_XOR):
            raise Exception('The passed memory card \'%s\' contains an '
                            'invalid control block (block 0), and is '
                            'therefore corrupt' % self.path)

        # Looping for all block-describing frames in the control block,
        # ignoring its own frame... (remember that the end of the range
        # given is the desired end + 1)
        for blockNumber in range(1, 16):

            # Verbose output
            if options.verbose:
                print('\nParsing block %d metadata...' % blockNumber)

            # Determining current offset (the metadata is maintained in one
            # frame per block described)
            offset = blockNumber * FRAME_SIZE

            # Making sure the frame is valid - XORing all but last byte and
            # comparing later to stored XOR (last byte) - this is a warning
            # rather than an error, since my Tomb Raider - The Last Revelation
            # save's first block in the multiblock save has calculated XOR 124
            # stored XOR 123 and works fine on PS2 - Gran Turismo and Gran
            # Turismo 2 are other examples. Testing GT1 specifically, copying
            # the save to a different card and reimaging results in exactly
            # the same XOR failure - yet the save loads fine on the PS2. It
            # flat out doesnt on the Pandora, but there'll be another reason
            # for that. Because it works on the console, I think this isn't a
            # real example of corruption
            accumulator = 0
            for byteAddress in range(offset, offset + FRAME_SIZE - 1):
                accumulator ^= controlBlock[byteAddress]
            if accumulator != controlBlock[offset + FRAME_SIZE - 1]:
                print('Warning: The passed memory card \'%s\' contains an'
                ' invalid frame in the control block (frame %d of block 0'
                ' which describes block %d), and is therefore in theory '
                'corrupt. However, I have examples of multiblock saves '
                'where they appear to work fine - so just raising a '
                'warning\n\n'
                'Calculated XOR value: %s\nRecorded value: %s\n' %
                (self.path, blockNumber, blockNumber, accumulator,
                 controlBlock[offset + FRAME_SIZE - 1]), file=sys.stderr)

            # Debug code
            #print('accumulator: %d\nActual XOR: %d' % (accumulator,
            #                          controlBlock[offset + FRAME_SIZE - 1]))

            # Is block in use, a normal block, a link block (and where the
            # link is relatively in a multi-block save) or unusable
            blockStatus = controlBlock[offset]

            # Checking block status
            if (blockStatus == 0x51 or blockStatus == 0xA1):

                # First block on its own or the first block in a multiblock
                # save, or the block is deleted (still reporting as it may
                # contain a recoverable save)
                # How many blocks the save consists of. This is only valid if
                # the block is the first block in the save - otherwise its
                # always 1 block long
                saveLength = controlBlock[offset + 4:offset + 7]

                # Location of next block of multi-block save - not sure how
                # useful this is?
                saveNextBlock = controlBlock[offset + 8:offset + 10]

                # Country (region rather) code
                countryCode = controlBlock[offset + 10:offset + 12]

                # The game code - printed on the spine of game case insert
                productCode = controlBlock[offset + 12:offset + 22]

                # Identifier unique to the game and playthrough/session in
                # progress (new game = new playthrough)
                gamePlayThroughIdentifier = controlBlock[offset + 22:offset + 31]

            elif (blockStatus == 0x52 or blockStatus == 0x53 or
                  blockStatus == 0xA0):

                # Block is in the middle or at the end of a multiblock save,
                # or is unused
                # Setting variables to None
                # It seems in linked saves, middle blocks onwards have old
                # (past save?) data saved in these metadata frames, and are
                # therefore invalid
                gamePlayThroughIdentifier = productCode = countryCode = saveNextBlock = saveLength = None

            # Delete (0xA1) is already handled in single block case

            elif blockStatus == 0xFF:

                # Block is unusable - no XOR check needed - warning user
                print('Warning: The passed memory card \'%s\' contains block '
                      '%d which is flagged as unusable' % (self.path,
                                                blockNumber), file=sys.stderr)

                # Setting variables to None
                gamePlayThroughIdentifier = productCode = countryCode = saveNextBlock = saveLength = None

            else:

                # Invalid block status detected - erroring
                raise Exception('The passed memory card \'%s\' contains '
                                'block %d that has an invalid (unknown) '
                                'status (\'%s\') - described in block 0 frame'
                                '%d' % (self.path, blockNumber, blockStatus,
                                        blockNumber))

            # Instantiating memory card block object and saving - note that
            # this is missing the save title, which is contained in the
            # actual block itself
            self[blockNumber] = PS1CardBlock(blockNumber, blockStatus,
                                            saveLength, saveNextBlock,
                                            countryCode, productCode,
                                            gamePlayThroughIdentifier)

        # Resetting offset
        offset = self.format_offset()

        # Control block has been parsed - looping for all other blocks
        if options.verbose:
            print('Control block parsing complete. Parsing actual blocks...')
        for blockNumber in range(1, 16):

            # Fetching current block and saving (skips block 0)
            offset += BLOCK_SIZE
            block = self.image[offset:offset + BLOCK_SIZE]
            self[blockNumber].data = block

            # Verbose output
            if options.verbose:
                print('\nParsing block %d, bytes %d to %d...'
                      % (blockNumber, offset, offset + BLOCK_SIZE - 1))

            # Checking for a normal one-block save or the first block in a
            # multiblock save
            if (block[:len(BLOCK_NORMAL_MAGIC)] == BLOCK_NORMAL_MAGIC):

                # Block is normal/first of a multiblock save - obtaining
                # save title - Shift-JIS encoded. This looks like the
                # characters are double-spaced, but according to the bits
                # they aren't... all 3 shift-jis encodings look like arse
                self[blockNumber].title = self.shift_jis_decoder(block[4:68])

                # Verbose output
                if options.verbose:
                    print('Block %d save title: \'%s\'' % (blockNumber,
                                                    self[blockNumber].title))

            else:

                # Block is linked as part of a multiblock save - pure data
                # Verbose output
                if options.verbose:
                    print('Block %d is a linked block' % blockNumber)

    def shift_jis_decoder(self, titleBytes):
        '''Attempt to decode passed bytes via shift-jis encoding, discarding
        any invalid/non-printable bytes at the end'''

        # Most save titles use valid shift-jis, but some leave crap data
        # straight after the title

        # Permissive encoding to get the basic valid string
        title = titleBytes.decode('shift-jis', 'replace')

        # Searching for the first control character - this appears to end the
        # user-valid data
        for i in range(len(title)):
            if unicodedata.category(title[i]) == 'Cc':

                # Control character found - breaking after setting valid title
                title = title[:i]
                break

        # Returning valid title
        return title

    # Debug code
    # Note the leading 'b and trailing '
    #print('Control block:\n\n%s' % controlBlock.translate(translationTable))


class PS1CardBlock(object):

    def __init__(self, blockNumber, blockStatus, saveLength, saveNextBlock,
                 countryCode, productCode, gamePlayThroughIdentifier):

        # Initialising variables
        self.blockNumber = blockNumber
        self._blockStatus = blockStatus
        self._saveLength = saveLength
        self._saveNextBlock = saveNextBlock
        self._countryCode = countryCode
        self._productCode = productCode
        self._gamePlayThroughIdentifier = gamePlayThroughIdentifier
        self._title = None  # This is set when blocks themselves are parsed

        # Verbose output
        if options.verbose:
            print('Initialising memory card block %(blockNumber)d:\n'
                  'blockStatus: %(blockStatus)s\n'
                  'saveLength: %(saveLength)s\n'
                  'saveNextBlock: %(saveNextBlock)s\n'
                  'countryCode: %(countryCode)s\n'
                  'productCode: %(productCode)s\n'
                  'gamePlayThroughIdentifier: %(gamePlayThroughIdentifier)s'
                  % {'blockNumber': blockNumber,
                     'blockStatus': blockStatus,
                     'saveLength': saveLength,
                     'saveNextBlock': saveNextBlock,
                     'countryCode': countryCode,
                     'productCode': productCode,
                     'gamePlayThroughIdentifier': gamePlayThroughIdentifier}
                  )

    # blockStatus property, not allowed to set
    def _get_blockStatus(self):

        # Returning useful form of blockStatus via lookup
        return BLOCK_STATUS[self._blockStatus]

    blockStatus = property(_get_blockStatus)

    # countryCode property, not allowed to set
    def _get_countryCode(self):

        # Checking if the block contains reportable data
        if not BLOCK_VALID_INFORMATION[self._blockStatus]:

            # It doesnt
            return '-'
        else:

            # It does - returning useful form of country code via lookup. Note
            # that this keeps the b''... might need to redefine binary
            # str somehow??
            return '%s (%s)' % (COUNTRY_CODE[self._countryCode],
                                self._countryCode)

    countryCode = property(_get_countryCode)

    # filename property, not allowed to set
    def _get_filename(self):

        # Checking if the block contains reportable data
        if not BLOCK_VALID_INFORMATION[self._blockStatus]:

            # It doesnt
            return '-'
        else:

            # It does. 'File name' as named by the PS3devwiki article is a
            # concatenation of other identifiers
            return str(self._countryCode + self.productCode +
                    self.gamePlayThroughIdentifier)

    filename = property(_get_filename)

    # gamePlayThroughIdentifier property, not allowed to set
    def _get_gamePlayThroughIdentifier(self):

        # Checking if the block contains reportable data
        if not BLOCK_VALID_INFORMATION[self._blockStatus]:

            # It doesnt
            return '-'
        else:

            # It does - valid gamePlayThroughIdentifier available - stripping
            # trailing null bytes
            return self._gamePlayThroughIdentifier.rstrip(b'\x00')

    gamePlayThroughIdentifier = property(_get_gamePlayThroughIdentifier)

    # productCode property, not allowed to set
    def _get_productCode(self):

        # Checking if the block contains reportable data
        if not BLOCK_VALID_INFORMATION[self._blockStatus]:

            # It doesnt
            return '-'
        else:

            # It does - valid product code available
            return self._productCode

    productCode = property(_get_productCode)

    # saveLength property, not allowed to set
    def _get_saveLength(self):

        # Checking if the block contains reportable data
        if not BLOCK_VALID_INFORMATION[self._blockStatus]:

            # It doesnt
            return '-'
        else:

            # It does - valid save length available
            return SAVE_LENGTH[self._saveLength]

    saveLength = property(_get_saveLength)

    # title property, allowed to get and set
    def _get_title(self):

        # Checking if the block contains reportable data
        if not BLOCK_VALID_INFORMATION[self._blockStatus]:

            # It doesnt
            return '-'
        else:

            # It does - valid title available
            return self._title

    def _set_title(self, title):
        self._title = title

    title = property(_get_title, _set_title)


# Configuring and parsing passed options
# TODO: Write up about type checking here
parser = OptionParser(version=('%%prog %s%s' % (VERSION, GPL_NOTICE)))
parser.add_option('-l', '--list', dest='list', help='list contents of memory '
'card image', metavar='list', action='store_true', default=False)
parser.add_option('-o', '--output', dest='output', help='path to output file',
metavar='output', default=None)
parser.add_option('-v', '--verbose', dest='verbose', help='output useful '
'information about what the program is doing', action='store_true',
default=False)
parser.add_option('-x', '--extract', dest='extract', type='int',
help='extract the data region of a save (without the header) beginning from '
'the desired block further blocks included if it is a multiblock save) to the'
' file specified in --output, or \'<memory card image path>.block_<block '
'number>.bin\' by default', metavar='extract', default=None)
(options, args) = parser.parse_args()

if args:

    # Making sure only one mode is used at once
    if (options.list + bool(options.extract)) > 1:
        print(parser.get_usage() + '\nOnly one mode can be enabled at once\n',
              file=sys.stderr)
        sys.exit(1)

    # Verbose output
    if options.verbose:
        print('Memory card to analyse: \'%s\'' % args[0])

    # Instantiating memory card
    memoryCard = PS1Card(args[0])

    if options.extract:

        # Extracting block(s) from memory card image
        # Validating block requested (tests such as '<block number> in
        # memoryCard' seem to fail as this works on identities rather than just
        # the number?)
        try:
            block = memoryCard[options.extract]

        except Exception:

            print('\nThe requested block to extract (\'%s\') is not valid\n'
                  % options.extract, file=sys.stderr)
            sys.exit(1)

        # Making sure the passed block is the first block of a save, or at
        # least a deleted block
        if (block.blockStatus != 'First block' and
            block.blockStatus != 'Deleted block'):
            print('\nThe requested block to extract (\'%s\') is neither the '
                  'first block of a save or a deleted block - status: \'%s\'n'
                  % (options.extract, block.blockStatus), file=sys.stderr)
            sys.exit(1)

        # Determining outputPath
        if options.output:
            outputPath = options.output
        else:
            outputPath = '%s.block_%d.bin' % (args[0], options.extract)

        # Turning into an absolute path
        outputPath = os.path.abspath(outputPath)

        # Extracting
        memoryCard.extract(options.extract, outputPath)

    elif options.list:

        # Listing contents
        memoryCard.list()

    else:

        # Invalid options
        parser.print_help()

else:

    # Optparse does not properly deal with no arguments, so this needs to be
    # manually handled
    parser.print_help()
