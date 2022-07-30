package org.dddjjj.datastruct.BTree;

import org.dddjjj.datastruct.B_Tree.BTree;
import org.junit.Test;

import java.util.Collection;

import static org.junit.Assert.assertTrue;

public class BTreeTest {
    @Test
    public void testBTree() {
        Utils.TestData data = Utils.generateTestData(1000);

        String bstName = "B-Tree";
        BTree<Integer> bst = new BTree<Integer>(2);
        Collection<Integer> bstCollection = bst.toCollection();

        assertTrue(TreeTest.testTree(bst, Integer.class, bstName, data.unsorted, data.invalid));
        assertTrue(JavaCollectionTest.testCollection(bstCollection, Integer.class, bstName,
                data.unsorted, data.sorted, data.invalid));
    }
}
