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

import unittest

from os import path

from zelos import Zelos
from zelos.threads import ThreadState


DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class ThreadManagerTest(unittest.TestCase):
    def test_swapWithNextThread_oneThread(self):
        z = Zelos(None)

        tman = z.internal_engine.thread_manager
        self.assertIsNone(tman.current_thread)

        tman.new_thread(0x1000, 0x1234, name="thread_1", priority=1)
        self.assertIsNone(tman.current_thread)
        self.assertEqual(1, tman.num_active_threads())

        tman.swap_with_next_thread()
        self.assertIsNotNone(tman.current_thread)
        self.assertEqual(1, tman.num_active_threads())

    def test_swapWithThread_oneThread(self):
        z = Zelos(None)

        tman = z.internal_engine.thread_manager
        self.assertIsNone(tman.current_thread)

        thread_1 = tman.new_thread(0x1000, 0x1234, name="thread_1", priority=1)
        self.assertIsNone(tman.current_thread)
        self.assertEqual(1, tman.num_active_threads())

        tman.swap_with_thread(tid=thread_1.id)
        self.assertIsNotNone(tman.current_thread)
        self.assertEqual(1, tman.num_active_threads())

    def test_swapWithNextThread_TwoThreads(self):
        z = Zelos(None)

        tman = z.internal_engine.thread_manager
        self.assertIsNone(tman.current_thread)

        tman.new_thread(0x1000, 0x1234, name="thread_1", priority=1)
        tman.new_thread(0x2000, 0x1235, name="thread_2", priority=1)
        self.assertIsNone(tman.current_thread)
        self.assertEqual(2, tman.num_active_threads())

        tman.swap_with_next_thread()
        self.assertIsNotNone(tman.current_thread)
        self.assertEqual(2, tman.num_active_threads())
        self.assertEqual("thread_1", tman.current_thread.name)

        tman.swap_with_next_thread()
        self.assertIsNotNone(tman.current_thread)
        self.assertEqual("thread_2", tman.current_thread.name)
        self.assertEqual(2, tman.num_active_threads())

    def test_changeThreadPriority(self):
        z = Zelos(None)

        tman = z.internal_engine.thread_manager
        self.assertIsNone(tman.current_thread)

        tman.new_thread(0x1000, 0x1234, name="thread_1", priority=1)
        tman.new_thread(0x2000, 0x1235, name="thread_2", priority=2)
        tman.new_thread(0x2000, 0x1236, name="thread_3", priority=3)

        tman.swap_with_next_thread()
        self.assertIsNotNone(tman.current_thread)
        self.assertEqual(3, tman.num_active_threads())
        self.assertEqual("thread_3", tman.current_thread.name)

        tman._reset()
        self.assertIsNone(tman.current_thread)

        tman.new_thread(0x1000, 0x1234, name="thread_1", priority=1)
        tman.new_thread(0x2000, 0x1235, name="thread_2", priority=2)
        tman.new_thread(0x2000, 0x1236, name="thread_3", priority=3)

        tman.change_thread_priority("thread_3", 1)
        tman.change_thread_priority("thread_1", 3)

        tman.swap_with_next_thread()
        self.assertIsNotNone(tman.current_thread)
        self.assertEqual(3, tman.num_active_threads())
        self.assertEqual("thread_1", tman.current_thread.name)

        tman.swap_with_next_thread()
        self.assertEqual("thread_1", tman.current_thread.name)

        tman.change_thread_priority("thread_1", 1)
        tman.swap_with_next_thread()
        self.assertEqual("thread_2", tman.current_thread.name)

    def test_save_after_edit(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        tman = z.internal_engine.thread_manager
        tman.swap_with_next_thread()

        self.assertIsNotNone(tman.current_thread)
        self.assertEqual(1, tman.num_active_threads())
        self.assertEqual(tman.current_thread.state, ThreadState.RUNNING)
        data = tman._save_state()

        tman.pause_current_thread()
        self.assertEqual(0, tman.num_active_threads())

        tman._load_state(data)
        self.assertIsNotNone(tman.current_thread)
        self.assertEqual(1, tman.num_active_threads())
        self.assertEqual(tman.current_thread.state, ThreadState.RUNNING)

        tman.pause_current_thread()
        self.assertEqual(0, tman.num_active_threads())

        tman._load_state(data)
        self.assertIsNotNone(tman.current_thread)
        self.assertEqual(1, tman.num_active_threads())
        self.assertEqual(tman.current_thread.state, ThreadState.RUNNING)

    def test_saveload(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        tman = z.internal_engine.thread_manager
        tman._reset()

        tman.new_thread(0x1000, 0x1234, name="thread_1", priority=1)
        tman.new_thread(0x2000, 0x1235, name="thread_2", priority=2)
        tman.new_thread(0x2000, 0x1236, name="thread_3", priority=3)
        tman.swap_with_next_thread()

        data = tman._save_state()
        self.assertEqual(3, tman.num_active_threads())

        tman._reset()
        tman._load_state(data)
        self.assertIsNotNone(tman.current_thread)
        self.assertEqual(3, tman.num_active_threads())
        self.assertEqual("thread_3", tman.current_thread.name)

    def test_saveload_current_thread_none(self):
        z = Zelos(path.join(DATA_DIR, "static_elf_helloworld"))
        tman = z.internal_engine.thread_manager
        tman._reset()

        tman.new_thread(0x1000, 0x1234, name="thread_1", priority=1)
        tman.new_thread(0x2000, 0x1235, name="thread_2", priority=2)
        tman.new_thread(0x2000, 0x1236, name="thread_3", priority=3)
        self.assertIsNone(tman.current_thread)
        data = tman._save_state()
        self.assertEqual(3, tman.num_active_threads())
        tman.swap_with_next_thread()

        tman._load_state(data)
        self.assertIsNone(tman.current_thread)
        self.assertEqual(3, tman.num_active_threads())

    def test_get_thread_by_name(self):
        z = Zelos(None)
        tman = z.internal_engine.thread_manager
        tman.new_thread(0x1000, 0x1234, name="thread_1", priority=1)
        tman.new_thread(0x2000, 0x1235, name="thread_2", priority=2)
        t = tman.get_thread_by_name("thread_1")
        self.assertIsNotNone(t)
        self.assertEqual(t.priority, 1)

        t = tman.get_thread_by_name("thread_3")
        self.assertIsNone(t)

    def test_block_counts(self):
        z = Zelos(None)
        tman = z.internal_engine.thread_manager
        main_thread = tman.new_thread(0x1000, 0x1234, name="main", priority=1)
        child_thread = tman.new_thread(
            0x1000, 0x1235, name="child", priority=1
        )
        tman.swap_with_thread(tid=main_thread.id)
        tman.record_block(0x1000)
        tman.record_block(0x2000)
        tman.record_block(0x1000)
        tman.record_block(0x3000)

        self.assertTrue(tman.block_seen_before(0x2000))
        self.assertFalse(tman.block_seen_before(0x2010))

        tman.swap_with_thread(tid=child_thread.id)
        tman.record_block(0x1000)
        tman.record_block(0x4000)

        self.assertEqual(tman.num_unique_blocks(thread_name="main"), 3)
        self.assertEqual(tman.num_unique_blocks(thread_name="child"), 2)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
