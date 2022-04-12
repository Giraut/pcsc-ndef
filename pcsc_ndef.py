#!/usr/bin/python3
"""Utility to read or write NDEF data to/from a NFC forum type 2 or type 4 tag
using PC/SC

Usage examples:

pcsc_ndef.py -t2 read > data.ndef   # Read NDEF from a T2 tag, output to stdout
pcsc_ndef.py -t4 read -o data.ndef  # Read NDEF from a T4 tag, save to a file
pcsc_ndef.py -t2 write < data.ndef  # Write NDEF from stdin
pcsc_ndef.py -t4 write -i data.ndef # Write NDEF from a file
pcsc_ndef.py -t2 -w2 read           # Read NDEF, wait for tag no longer than 2s
pcsc_ndef.py -t4 -w0 read           # Read NDEF, fail at once if no tag present
pcsc_ndef.py -r ACS -t2 read        # Use first reader whose name contains "ACS"
pcsc_ndef.py -h                     # Display help
pcsc_ndef.py read -h                # Display help on the read command
pcsc_ndef.py write -h               # Display help on the write command
"""

### Parameters
default_reader = "0"
default_tag_wait = -1 #s	# -1 to wait forever for a tag to read or write
default_read_output_file = "-"	# "-" outputs the NDEF to stdout
default_write_input_file = "-"	# "-" inputs the NDEF from stdin



### Modules
import re
import sys
import argparse
from time import time,sleep
import smartcard.scard as sc



### Classes
class pcsc_ndef():
  """Class to read or write NDEFs to NFC forum type 2 or type 4 tags using PC/SC
  """

  # Defines
  CC_MAGIC = 0xe1
  NDEF_TAG = 0x03
  TERMINATOR_TAG = 0xfe

  NDEF_AID = "d2760000850101"
  NDEF_CAPA_FID = "e103"

  INS_SELECT = 0xa4
  P1_SELECT_AID = 0x04
  P2_SELECT_AID = 0x00
  P1_SELECT_FID = 0x00
  P2_SELECT_FID = 0x0c

  INS_READ = 0xb0
  INS_WRITE = 0xd6

  SW1_OK = 0x90
  SW2_OK = 0x00

  NDEF_FILE_CTL_TAG = 0x04



  def __init__(self):
    """__init__ method
    """

    self.readers_regex = "^.*$"

    self.ndef_aid = list(bytes.fromhex(self.NDEF_AID))
    self.ndef_capa_fid = list(bytes.fromhex(self.NDEF_CAPA_FID))

    self.all_readers = []
    self.hcontext = None

    self.reader = None



  def set_readers_regex(self, reader):
    """Construct the readers regex from the string supplied by the user and
    force the reader to be updated
    """

    self.readers_regex = "^.*{}.*$".format(reader)
    self.all_readers = []



  def _send_apdu(self, hcard, dwActiveProtocol, apdu):
    """Send an APDU command, get the response.
    Returns (None, None, r, response) if no error,
    (errmsg, err_critical_flag, None, None) otherwise.
    """

    try:
      r, response = sc.SCardTransmit(hcard, dwActiveProtocol, apdu)

    except Exception as e:
      return (repr(e), True, None, None)

    if len(response) < 2:
      return ("APDU response too short", False, None, None)

    return (None, None, r, response)



  def rw_ndef(self, tagtype, data = None, progress_feedback = None):
    """Try to establish communication with the tag, then read or write NDEF
    data to/from it. if data is None, the NDEF is read and returned. If not,
    the NDEF data is written.
    If a function is passed in progress_feedback, this function is called with
    the number of bytes read or written, the total number of bytes to read or
    write at each chunk read or written, and whether it's called for the last
    time or not.
    Returns (None, None, ...) if no error, (errmsg, err_critical_flag, None)
    otherwise.
    """

    errmsg = None
    errcritical = True

    disconnect_card = False
    release_ctx = False

    while True:

      # If we arrive here needing to either disconnect the card or release the
      # PC/SC resource manager context, do so and break the loop
      if disconnect_card or release_ctx:

        if disconnect_card:
          try:
            sc.SCardDisconnect(hcard, sc.SCARD_UNPOWER_CARD)
          except:
            pass

        if release_ctx:
          try:
            sc.SCardReleaseContext(self.hcontext)
          except:
            pass
          del(self.hcontext)
          self.hcontext = None

        break

      # Get the PC/SC resource manager context
      if not self.hcontext:
        try:
          r, self.hcontext = sc.SCardEstablishContext(sc.SCARD_SCOPE_USER)

        except Exception as e:
          errmsg = "error getting PC/SC resource manager context: {}".format(e)
          break

        if r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "cannot establish PC/SC resource manager context"
          continue

      # Get the current list of readers
      try:
        _, all_readers_new = sc.SCardListReaders(self.hcontext, [])

      except Exception as e:
        release_ctx = True
        errmsg = "error getting the list of readers: {}".format(e)
        continue

      if not all_readers_new:
        self.all_readers = []
        errmsg = "no readers"
        break

      # Get the first reader that matches the regex
      if all_readers_new != self.all_readers:
        self.all_readers = all_readers_new

        for r in self.all_readers:
          if re.match(self.readers_regex, r, re.I):
            self.reader = r
            break

        else:
          self.reader = None

      # Do we have a reader to read from?
      if self.reader is None:
        errmsg = "no matching readers"
        break

      # Connect to the smartcard
      try:
        r, hcard, dwActiveProtocol = sc.SCardConnect(self.hcontext,
							self.reader,
							sc.SCARD_SHARE_SHARED,
							sc.SCARD_PROTOCOL_T0 | \
							sc.SCARD_PROTOCOL_T1)

      except Exception as e:
        release_ctx = True
        errmsg = "error connecting to the smartcard: {}".format(e)
        continue

      if r != sc.SCARD_S_SUCCESS:
        errmsg = "error connecting to the smartcard"
        errcritical = False
        break

      # Whatever happens next, try to disconnect the card before returning
      disconnect_card = True



      # Process a NFC forum type 2 tag
      if tagtype == "2":

        # Read the capabilities container
        errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0xff, self.INS_READ, 0x00, 0x03, 4])

        if errmsg or r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "error transmitting the read binary command (reading " \
			"4-byte CC at page 3){}".format(
			": {}".format(errmsg) if errmsg else "")
          errcritical = False
          continue

        # Did we get a response error?
        if response[-2:] != [self.SW1_OK, self.SW2_OK]:
          errmsg = "error {:02X}{:02X} from read binary command (reading " \
			"4-byte CC at page 3)".format(
			response[-2], response[-1])
          errcritical = False
          continue

        response = response[:-2]

        # Did we get the correct length of data?
        if len(response) != 4:
          errmsg = "requested 4 bytes at page 3 in read command, got {}".\
			format(len(response))
          continue

        # Extract the data we need from the capabilities container and check
        # that it's valid
        if response[0] != self.CC_MAGIC:
          errmsg = "invalid capability container: incorrect magic number " \
			"{:02X}".format(response[0])
          continue

        data_area_size = response[2] * 8

        # Calculate the maximum size of the NDEF
        max_ndef_size = data_area_size - 2	# Assume a 2-byte NDEF tag + len
        if max_ndef_size >= 0xff:
          max_ndef_size -= 2	# ...and correct for a 3 byte length if the size
				# is over 0xff
        max_ndef_size -= 2	# ...then subtract the space taken up by the
				# terminator TLV

        # Make sure the NDEF will fit if we write it
        if data is not None and len(data) > max_ndef_size:
          errmsg = "NDEF exceeds tag's capacity (max. {} bytes)".\
			format(max_ndef_size)
          continue

        # Read the NDEF
        if data is None:

          read_sched = [[4, 4]]	# Start by reading the NDEF TLV's tag and length

          # Read chunks of data scheduled to be read
          while read_sched and not errmsg:

            rpoffset, rlen = read_sched.pop(0)

            # Read the chunk of data. Only read whole chunks of 4 bytes for
            # safety, then trim the data ourselves
            errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0xff, self.INS_READ,
					rpoffset >> 8, rpoffset & 0xff, 4])

            if errmsg or r != sc.SCARD_S_SUCCESS:
              release_ctx = True
              errmsg = "error transmitting the read binary command " \
			"(reading {} bytes at page offset {}){}".format(
			rlen, rpoffset, ": {}".format(errmsg) if errmsg else "")
              if progress_feedback and data is not None:
                progress_feedback(len(data), ndef_size, lasttime = True)
              continue

            # Did we get a response error?
            if response[-2:] != [self.SW1_OK, self.SW2_OK]:
              errmsg = "error {:02X}{:02X} from read binary command " \
			"(reading {} bytes at page offset {})".format(
			response[-2], response[-1], rlen, rpoffset)
              if progress_feedback and data is not None:
                progress_feedback(len(data), ndef_size, lasttime = True)
              continue

            response = response[:-2]

            # Did we get the correct length of data?
            if len(response) != 4:
              errmsg = "requested 4 bytes at page offset {} in read binary "\
			"command, got {}".format(rpoffset, len(response))
              if progress_feedback and data is not None:
                progress_feedback(len(data), ndef_size, lasttime = True)
              continue

            # Trim the response
            response = response[:rlen]

            # Did we get the TLV (and possibly a  bit of the NDEF data)?
            if data is None:

              # Check that we have the correct TLV TAG
              if response[0] != self.NDEF_TAG:
                errmsg = "invalid NDEF TLV tag {:02X} or no NDEF".\
				format(response[0])
                continue

              ndef_size = response[1] if response[1] < 0xff else \
				(response[2] << 8) + response[3]

              # Make sure the size of the NDEF looks valid
              if not 0 < ndef_size <= max_ndef_size:
                errmsg = "tag reported invalid NDEF size of {} bytes".\
			format(ndef_size)
                continue

              # If the NDEF size is encoded on 1 byte, we already read 2 bytes
              # of NDEF data - unless the NDEF is less than 2 bytes
              data = b"" if response[1] == 0xff else \
			bytes(response[2:4][:ndef_size])

              # Schedule the page offsets and lengths needed to read the rest
              # of the NDEF data
              rpoffset = 5
              bytes_remaining = ndef_size - len(data)

              while bytes_remaining:
                rlen = min(4, bytes_remaining)
                read_sched.append([rpoffset, rlen])
                rpoffset += 1
                bytes_remaining -= rlen

            # We got a chunk of NDEF data
            else:

              data += bytes(response)

            # Call the progress feedback function if we have one
            if progress_feedback:
              progress_feedback(len(data), ndef_size,
				lasttime = len(data) == ndef_size)

          if errmsg:
            continue

        # Write the NDEF
        else:

          write_sched = []

          # Add the NDEF tag and length at the start of the NDEF to form the
          # NDEF TLV
          ndef_size = len(data)
          tl = [self.NDEF_TAG, ndef_size] if ndef_size < 0xff else \
		[self.NDEF_TAG, 0xff, ndef_size >> 8, ndef_size & 0xff]
          data = tl + list(data)
          ndef_size += len(tl)

          # Add the terminator TLV at the end of the NDEF TLV
          data += [self.TERMINATOR_TAG, 0x00]
          ndef_size += 2

          # Schedule the page offsets and lengths needed to write the
          # encapsulated NDEF data
          wpoffset = 4
          woffset = 0
          bytes_remaining = ndef_size

          while bytes_remaining:
            wlen = min(4, bytes_remaining)
            write_sched.append([wpoffset, woffset, wlen])
            wpoffset += 1
            woffset += wlen
            bytes_remaining -= wlen

          # If the last block scheduled to be written isn't exactly 4 bytes
          # long, read the corresponding block in the tag's memory to fetch
          # existing bytes to pad the new data
          wpoffset, woffset, wlen = write_sched[-1]

          if wlen < 4:

            errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0xff, self.INS_READ,
					wpoffset >> 8, wpoffset & 0xff, 4])

            if errmsg or r != sc.SCARD_S_SUCCESS:
              release_ctx = True
              errmsg = "error transmitting the read binary command (reading " \
			"4 bytes at page {}){}".format(wpoffset,
			": {}".format(errmsg) if errmsg else "")
              continue

            # Did we get a response error?
            if response[-2:] != [self.SW1_OK, self.SW2_OK]:
              errmsg = "error {:02X}{:02X} from read binary command (reading " \
			"4 bytes at page {})".format(wpoffset,
			response[-2], response[-1])
              continue

            response = response[:-2]

            # Did we get the correct length of data?
            if len(response) != 4:
              errmsg = "requested 4 bytes at page {} in read command, got {}".\
			format(wpoffset, len(response))
              continue

            # Pad our data with existing data
            data += response[wlen:4]
            write_sched[-1][2] = 4
            ndef_size = len(data)

          # Call the progress feedback function if we have one
          if progress_feedback:
            progress_feedback(0, ndef_size, lasttime = False)

          # Write chunks of data scheduled to be written
          written = 0
          while write_sched and not errmsg:

            wpoffset, woffset, wlen = write_sched.pop(0)

            # Write the chunk of data
            errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0xff, self.INS_WRITE,
					wpoffset >> 8, wpoffset & 0xff, wlen] +\
					data[woffset : woffset + wlen])

            if errmsg or r != sc.SCARD_S_SUCCESS:
              release_ctx = True
              errmsg = "error transmitting the update binary command "\
			"(writing {} bytes at page offset {}){}".format(
			wlen, wpoffset, ": {}".format(errmsg) if errmsg else "")
              if progress_feedback:
                progress_feedback(written, ndef_size, lasttime = True)
              continue

            # Did we get a response error?
            if response[-2:] != [self.SW1_OK, self.SW2_OK]:
              errmsg = "error {:02X}{:02X} from update binary command " \
			"(writing {} bytes at page offset {})".format(
			response[-2], response[-1], wlen, wpoffset)
              if progress_feedback:
                progress_feedback(written, ndef_size, lasttime = True)
              continue

            written = woffset + wlen

            # Call the progress feedback function if we have one
            if progress_feedback:
              progress_feedback(written, ndef_size,
				lasttime = written == ndef_size)

          data = None

          if errmsg:
            continue



      # Process a NFC forum type 4 tag
      elif tagtype == "4":

        # Select the NDEF application
        errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_SELECT,
					self.P1_SELECT_AID, self.P2_SELECT_AID,
					len(self.ndef_aid)] + self.ndef_aid)

        if errmsg or r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "error transmitting NDEF AID selection command{}".format(
			": {}".format(errmsg) if errmsg else "")
          errcritical = ec
          continue

        # Did we get a response error?
        if response[-2:] != [self.SW1_OK, self.SW2_OK]:
          errmsg = "error {:02X}{:02X} from NDEF AID selection command".format(
			response[-2], response[-1])
          errcritical = False
          continue

        # Select the NDEF capability container file
        errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_SELECT,
					self.P1_SELECT_FID, self.P2_SELECT_FID,
					len(self.ndef_capa_fid)] + \
					self.ndef_capa_fid)

        if errmsg or r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "error transmitting NDEF capabilities FID selection " \
			"command{}".format(
			": {}".format(errmsg) if errmsg else "")
          continue

        # Did we get a response error?
        if response[-2:] != [self.SW1_OK, self.SW2_OK]:
          errmsg = "error {:02X}{:02X} from NDEF capabilities FID selection " \
			"command".format(response[-2], response[-1])
          continue

        # Read the NDEF capability container file
        errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_READ, 0, 0, 15])

        if errmsg or r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "error transmitting NDEF capabilities file read command{}".\
			format(": {}".format(errmsg) if errmsg else "")
          continue

        # Did we get a response error?
        if response[-2:] != [self.SW1_OK, self.SW2_OK]:
          errmsg = "error {:02X}{:02X} from NDEF capabilities file read " \
			"command".format(response[-2], response[-1])
          continue

        response = response[:-2]

        # Check that the response is the right length and the file control TLV
        # is valid
        if len(response) != 15:
          errmsg = "NDEF capabilities file isn't 15 bytes long"
          continue

        if response[7] != self.NDEF_FILE_CTL_TAG or response[8] != 6:
          errmsg = "Invalid NDEF file control TLV in NDEF capabilities file"
          continue

        # Extract the data we need from the capabilities container
        max_r_apdu = (response[3] << 8) + response[4]
        max_c_apdu = (response[5] << 8) + response[6]
        ndef_data_fid = [response[9], response[10]]
        max_ndef_size = (response[11] << 8) + response[12]

        # Some tags (i.e. OpenJavaCard NDEF applet) seem to throw a fit and
        # return SW_WRONG_LENGTH (0x6700) if we try to read as much data per
        # response APDU as the CC advertises. Artificially limit the maximum
        # size of the response APDU as a workaround.
        max_r_apdu = 60

        max_ndef_size -= 2	# Count 2 leading bytes for the size

        # Make sure the NDEF will fit if we write it
        if data is not None and len(data) > max_ndef_size:
          errmsg = "NDEF exceeds tag's capacity (max. {} bytes)".\
			format(max_ndef_size)
          continue

        # Select the NDEF data file
        errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_SELECT,
					self.P1_SELECT_FID, self.P2_SELECT_FID,
					len(ndef_data_fid)] + ndef_data_fid)

        if errmsg or r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "error transmitting NDEF data FID selection command{}".\
			format(": {}".format(errmsg) if errmsg else "")
          continue

        # Did we get a response error?
        if response[-2:] != [self.SW1_OK, self.SW2_OK]:
          errmsg = "error {:02X}{:02X} from NDEF data FID selection command".\
			format(response[-2], response[-1])
          continue

        # Read the NDEF
        if data is None:

          read_sched = [[0, 2]]	# Start by reading the size of the NDEF

          # Read chunks of data scheduled to be read
          while read_sched and not errmsg:

            roffset, rlen = read_sched.pop(0)

            # Read the chunk of data
            errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_READ,
					roffset >> 8, roffset & 0xff, rlen])

            if errmsg or r != sc.SCARD_S_SUCCESS:
              release_ctx = True
              errmsg = "error transmitting the NDEF data read command " \
			"(reading {} bytes at offset {}){}".format(
			rlen, roffset, ": {}".format(errmsg) if errmsg else "")
              if progress_feedback and data is not None:
                progress_feedback(len(data), ndef_size, lasttime = True)
              continue

            # Did we get a response error?
            if response[-2:] != [self.SW1_OK, self.SW2_OK]:
              errmsg = "error {:02X}{:02X} from NDEF data read command " \
			"(reading {} bytes at offset {})".format(
			response[-2], response[-1], rlen, roffset)
              if progress_feedback and data is not None:
                progress_feedback(len(data), ndef_size, lasttime = True)
              continue

            response = response[:-2]

            # Did we get the correct length of data?
            if len(response) != rlen:
              errmsg = "requested {} bytes at offset {} in NDEF data read "\
			"command, got {}".format(rlen, roffset, len(response))
              if progress_feedback and data is not None:
                progress_feedback(len(data), ndef_size, lasttime = True)
              continue

            # Did we get the size of the NDEF?
            if data is None:

              ndef_size = (response[0] << 8) + response[1]

              # Make sure the size of the NDEF looks valid
              if not 0 < ndef_size <= max_ndef_size:
                errmsg = "tag reported invalid NDEF size of {} bytes".\
			format(ndef_size)
                continue

              # Schedule the offsets and lengths needed to read the rest of the
              # NDEF data
              roffset = 2
              bytes_remaining = ndef_size

              while bytes_remaining:
                rlen = min(max_r_apdu - 2, bytes_remaining)
                read_sched.append([roffset, rlen])
                roffset += rlen
                bytes_remaining -= rlen

              data = b""

            # We got a chunk of NDEF data
            else:

              data += bytes(response)

            # Call the progress feedback function if we have one
            if progress_feedback:
              progress_feedback(len(data), ndef_size,
				lasttime = len(data) == ndef_size)

          if errmsg:
            continue

        # Write the NDEF
        else:

          write_sched = []

          # Add the length of the NDEF at the start of the NDEF
          ndef_size = len(data)
          data = [ndef_size >> 8, ndef_size & 0xff] + list(data)
          ndef_size += 2

          # Schedule the offsets and lengths needed to write the NDEF data
          woffset = 0
          bytes_remaining = ndef_size

          while bytes_remaining:
            wlen = min(max_c_apdu - 5, bytes_remaining)
            write_sched.append([woffset, wlen])
            woffset += wlen
            bytes_remaining -= wlen

          # Call the progress feedback function if we have one
          if progress_feedback:
            progress_feedback(0, ndef_size, lasttime = False)

          # Write chunks of data scheduled to be written
          written = 0
          while write_sched and not errmsg:

            woffset, wlen = write_sched.pop(0)

            # Write the chunk of data
            errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_WRITE,
					woffset >> 8, woffset & 0xff, wlen] + \
					data[woffset : woffset + wlen])

            if errmsg or r != sc.SCARD_S_SUCCESS:
              release_ctx = True
              errmsg = "error transmitting the NDEF data write command "\
			"(writing {} bytes at offset {}){}".format(
			wlen, woffset, ": {}".format(errmsg) if errmsg else "")
              if progress_feedback:
                progress_feedback(written, ndef_size, lasttime = True)
              continue

            # Did we get a response error?
            if response[-2:] != [self.SW1_OK, self.SW2_OK]:
              errmsg = "error {:02X}{:02X} from NDEF data write command " \
			"(writing {} bytes at offset {})".format(
			response[-2], response[-1], wlen, woffset)
              if progress_feedback:
                progress_feedback(written, ndef_size, lasttime = True)
              continue

            written = woffset + wlen

            # Call the progress feedback function if we have one
            if progress_feedback:
              progress_feedback(written, ndef_size,
				lasttime = written == ndef_size)

          data = None

          if errmsg:
            continue

    return (errmsg, errcritical, data)



### Routines
def progress_feedback(nb, total, lasttime):
  """Print a progress feedback on stderr. If last is asserted, the function is
  called for the last time
  """

  stotal = str(total)
  snb = str(nb)
  print("{}{}{} / {} bytes".format("" if not nb else "\r",
					" " * (len(stotal) - len(snb)),
					nb, total), end = "", file = sys.stderr)
  if lasttime:
    print(file = sys.stderr)

  sys.stderr.flush()



### Main routine
def main():
  """Main program
  """

  # Parse the command line arguments
  argparser = argparse.ArgumentParser()
  subparsers = argparser.add_subparsers()
  subparsers.required = True
  subparsers.dest = "command"

  # Subparsers
  subparser_read = subparsers.add_parser(
	"read",
	help = "Read NDEF content from a tag"
	)

  subparser_write = subparsers.add_parser(
	"write",
	help = "Write NDEF content to a tag"
	)

  # Main parser's epilog
  argparser.epilog = "To get help on commands {}, invoke {} COMMAND -h".format(
			",".join([cmd.dest \
			for cmd in subparsers._get_subactions()]),
			argparser.prog)

  # Common arguments
  argparser.add_argument(
	"-r", "--reader",
	help = "Use first PC/SC reader whose name contains this argument. "
		"Default: {}".format(default_reader),
	type = str,
	default = default_reader
	)

  argparser.add_argument(
	"-w", "--wait",
	help = "Number of seconds to wait for a tag to read or write "
		"(-1 = wait forever). Default: {}".format(default_tag_wait),
	type = float,
	default = default_tag_wait
	)

  argparser.add_argument(
	"-t", "--type",
	help = "NFC forum tag type",
        choices = ["2", "4"],
        required = True
	)

  # Arguments applicable to the read command
  subparser_read.add_argument(
	"-o", "--output",
	help = "Output file (- = stdout). Default: {}".
		format(default_read_output_file),
	type = str,
	default = default_read_output_file
	)

  subparser_write.add_argument(
	"-i", "--input",
	help = "Input file (- = stdin). Default: {}".
		format(default_read_output_file),
	type = str,
	default = default_read_output_file
	)

  args = argparser.parse_args()

  # If we write the NDEF, read in the data to write
  if args.command == "write":

    if args.input == "-":
      data_in = sys.stdin.buffer.read()

    else:
      try:
        with open(args.input, "rb") as f:
          data_in = f.read()

      except Exception as e:
        print("Error reading {}: {}".format(args.input, e), file = sys.stderr)
        return -1

  # Read the NDEF
  else:
    data_in = None

  # Create a PC/SC NDEF reader/writer instance
  pn = pcsc_ndef()

  # Set the readers regex
  pn.set_readers_regex(args.reader)

  stop_wait_tstamp = time() + args.wait
  while True:

    # Try to read or write the NDEF data to/from the tag
    errmsg, errcritical, data_out = pn.rw_ndef(tagtype = args.type,
						data = data_in,
						progress_feedback = \
							progress_feedback)
    if errmsg and errcritical:
      print("Error {} NDEF: {}".format("reading" if data_in is None else \
					"writing", errmsg), file = sys.stderr)
      return -1

    # If the command succeeded or the wait time is exceeded, stop waiting
    if not errmsg or (args.wait >= 0 and time() > stop_wait_tstamp):
      break

    # Avoid a tight loop
    sleep(.1)

  if errmsg:
    print("No tag found", file = sys.stderr)
    return -1

  # Save the data or write it to stdout
  if data_out is not None:

    if args.output == "-":
      sys.stdout.buffer.write(data_out)

    else:
      try:
        with open(args.output, "wb") as f:
          f.write(data_out)

      except Exception as e:
        print("Error writing {}: {}".format(args.output, e), file = sys.stderr)
        return -1

  print("Done", file = sys.stderr)
  return 0



### Jump to the main routine
if __name__ == "__main__":
  exit(main())
