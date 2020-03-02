# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
# ======================================================================


class Pipe:
    """
    Class used to communicate information between processes similar
    to a linux pipe.
    """

    def __init__(self):
        self.buffer = b""
        self.write_end_closed = False
        self.read_end_closed = False

    def write(self, data: bytes) -> int:
        """
        Write data to the pipe's buffer. Returns the number of bytes
        written to buffer
        """
        self.buffer += data
        return len(data)

    def read(self, size=None) -> bytes:
        """
        Read data from the pipe's buffer up to the requested size.
        Defaults to reading the entire buffer
        """
        if size is None:
            size = len(self.buffer)
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def is_empty(self) -> bool:
        return len(self.buffer) == 0
