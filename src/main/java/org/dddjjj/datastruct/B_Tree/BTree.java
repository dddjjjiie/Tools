package org.dddjjj.datastruct.B_Tree;

/**
 * m = 2k + 1阶B树：
 * 1.内部节点最少子节点k + 1个子节点
 * 2.每个节点最多含有2k+1个子节点
 * 3.若根节点不是叶子节点，则至少有两个孩子节点
 * 4.所有叶子节点都出现在同一层
 * 5.节点的关键字比子节点数量少1
 * 6.关键字key的左子树中所有关键字都小于key,key的右子树中所有关键字都大于key
 */

import java.util.*;

public class BTree<T extends Comparable<T>> implements ITree<T>{
    private int minKeySize = 1;
    private int minChildrenSize = minKeySize + 1;
    private int maxKeySize = 2 * minKeySize;
    private int maxChildrenSize = maxKeySize + 1;

    private Node<T> root = null;
    private int size = 0;

    public BTree(){}

    public BTree(int order){
        this.minKeySize = order;
        this.minChildrenSize = minKeySize + 1;
        this.maxKeySize = 2 * minKeySize;
        this.maxChildrenSize = maxKeySize + 1;
    }

    @Override
    public boolean add(T value) {
        if(root == null){
            root = new Node(null, maxKeySize, maxChildrenSize);
            root.addKey(value);
        }else{
            Node<T> node = root;
            while(node != null){
                if(node.numberOfChildren() == 0){
                    node.addKey(value);
                    if(node.numberOfKeys() <= maxKeySize) break;
                    split(node);
                    break;
                }

                //boundary determination
                T lesser = node.getKey(0);
                if(value.compareTo(lesser) <= 0){
                    node = node.getChild(0);
                    continue;
                }

                int numberOfKeys = node.numberOfKeys();
                int last = numberOfKeys - 1;
                T greater = node.getKey(last);
                if(value.compareTo(greater) > 0){
                    node = node.getChild(numberOfKeys);
                    continue;
                }

                //internal keys
                for(int i=1; i<node.numberOfKeys(); i++){
                    T prev = node.getKey(i - 1);
                    T next = node.getKey(i);
                    if(value.compareTo(prev) > 0 && value.compareTo(next) <= 0){
                        node = node.getChild(i);
                        break;
                    }
                }
            }
        }
        size++;
        return true;
    }

    private void split(Node<T> nodeToSplit){
        Node<T> node = nodeToSplit;
        int numberOfKeys = node.numberOfKeys();
        int midIdx = numberOfKeys >> 1;
        T midVal = node.getKey(midIdx);

        Node<T> left = new Node<>(null, maxKeySize, maxChildrenSize);
        for(int i=0; i<midIdx; i++){
            left.addKey(node.getKey(i));
        }
        if(node.numberOfChildren() > 0){
            for(int j=0; j<=midIdx; j++){
                left.addChild(node.getChild(j));
            }
        }

        Node<T> right = new Node<>(null, maxKeySize, maxChildrenSize);
        for(int i=midIdx+1; i<numberOfKeys; i++){
            right.addKey(node.getKey(i));
        }
        if(node.numberOfChildren() > 0){
            for(int j=midIdx+1; j<node.numberOfChildren(); j++){
                right.addChild(node.getChild(j));
            }
        }

        if(node.parent == null){
            Node<T> newRoot = new Node<>(null, maxKeySize, maxChildrenSize);
            newRoot.addKey(midVal);
            node.parent = newRoot;
            root = newRoot;
            root.addChild(left);
            root.addChild(right);
        }else{
            Node<T> parent = node.parent;
            parent.addKey(midVal);;
            parent.removeChild(node);
            parent.addChild(left);
            parent.addChild(right);

            if(parent.numberOfKeys() > maxKeySize) split(parent);
        }
    }

    @Override
    public T remove(T value) {
        T removed = null;
        Node<T> node = getNode(value);
        removed = remove(value, node);
        return removed;
    }

    private T remove(T value, Node<T> node){
        if(node == null) return null;
        T removed = null;
        int idx = node.indexOf(value);
        removed = node.removeKey(value);
        if(node.numberOfChildren() == 0){ //leaf node
            if(node.parent != null && node.numberOfKeys() < minKeySize){
                this.combined(node);
            }else if(node.parent == null && node.numberOfKeys() == 0){
                root = null;
            }
        }else{ //non leaf node
            Node<T> lesser = node.getChild(idx);
            Node<T> greatest = this.getGreatestNode(lesser);
            T replaceValue = this.removeGreatestValue(greatest);
            node.addKey(replaceValue);
            if(greatest.parent != null && greatest.numberOfKeys() < minKeySize){
                this.combined(greatest);
            }
            if(greatest.numberOfChildren() > maxChildrenSize){
                this.split(greatest);
            }
        }
        size--;
        return removed;
    }

    private boolean combined(Node<T> node){
        Node<T> parent = node.parent;
        int idx = parent.indexOf(node);
        int indexOfLeftNeighbor = idx - 1;
        int indexOfRightNeighbor = idx + 1;

        Node<T> rightNeighbor = null;
        int rightNeighborSize = -minChildrenSize;
        if(indexOfRightNeighbor < parent.numberOfChildren()){
            rightNeighbor = parent.getChild(indexOfRightNeighbor);
            rightNeighborSize = rightNeighbor.numberOfKeys();
        }

        if(rightNeighbor != null && rightNeighborSize > minKeySize){
            T removeValue = rightNeighbor.getKey(0);
            int prev = getIndexOfPreviousValue(parent, removeValue);
            T parentValue = parent.removeKey(prev);
            T neighborValue = rightNeighbor.removeKey(0);
            node.addKey(parentValue);
            parent.addKey(neighborValue);
            if(rightNeighbor.numberOfChildren() > 0){
                node.addChild(rightNeighbor.removeChild(0));
            }
        }else{
            Node<T> leftNeighbor = null;
            int leftNeighborSize = -minChildrenSize;
            if(indexOfLeftNeighbor >= 0){
                leftNeighbor = parent.getChild(indexOfLeftNeighbor);
                leftNeighborSize = leftNeighbor.numberOfKeys();
            }
            if(leftNeighbor != null && leftNeighborSize > minKeySize){
                T removeValue = leftNeighbor.getKey(leftNeighbor.numberOfKeys() - 1);
                int next = getIndexOfNextValue(parent, removeValue);
                T parentValue = parent.removeKey(next);
                T neighborValue = leftNeighbor.removeKey(leftNeighbor.numberOfKeys() - 1);
                node.addKey(parentValue);
                parent.addKey(neighborValue);
                if(leftNeighbor.numberOfChildren() > 0){
                    node.addChild(leftNeighbor.removeChild(leftNeighbor.numberOfChildren() - 1));
                }
            }else if(rightNeighbor != null && parent.numberOfKeys() > 0){
                T removeValue = rightNeighbor.getKey(0);
                int prev = getIndexOfPreviousValue(parent, removeValue);
                T parentValue = parent.removeKey(prev);
                parent.removeChild(rightNeighbor);
                node.addKey(parentValue);
                for(int i=0; i<rightNeighbor.keysSize; i++){
                    node.addKey(rightNeighbor.getKey(i));
                }
                for(int i=0; i<rightNeighbor.childrenSize; i++){
                    node.addChild(rightNeighbor.getChild(i));
                }
                if(parent.parent != null && parent.numberOfKeys() < minKeySize){
                    this.combined(parent);
                }else if(parent.numberOfKeys() == 0){
                    node.parent = null;
                    root = node;
                }
            }else if(leftNeighbor != null && parent.numberOfKeys() > 0){
                T removeValue = leftNeighbor.getKey(leftNeighbor.numberOfKeys() - 1);
                int prev = getIndexOfNextValue(parent, removeValue);
                T parentValue = parent.removeKey(prev);
                parent.removeChild(leftNeighbor);
                node.addKey(parentValue);
                for(int i=0; i<leftNeighbor.keysSize; i++){
                    node.addKey(leftNeighbor.getKey(i));
                }
                for(int i=0; i<leftNeighbor.childrenSize; i++){
                    node.addChild(leftNeighbor.getChild(i));
                }
                if(parent.parent != null && parent.numberOfKeys() < minKeySize){
                    this.combined(parent);
                }else if(parent.numberOfKeys() == 0){
                    node.parent = null;
                    root = node;
                }
            }
        }
        return true;
    }

    private int getIndexOfPreviousValue(Node<T> node, T value) {
        for (int i = 1; i < node.numberOfKeys(); i++) {
            T t = node.getKey(i);
            if (t.compareTo(value) >= 0)
                return i - 1;
        }
        return node.numberOfKeys() - 1;
    }

    private int getIndexOfNextValue(Node<T> node, T value) {
        for (int i = 0; i < node.numberOfKeys(); i++) {
            T t = node.getKey(i);
            if (t.compareTo(value) >= 0)
                return i;
        }
        return node.numberOfKeys() - 1;
    }


    private Node<T> getGreatestNode(Node<T> nodeToGet) {
        Node<T> node = nodeToGet;
        while (node.numberOfChildren() > 0) {
            node = node.getChild(node.numberOfChildren() - 1);
        }
        return node;
    }

    private T removeGreatestValue(Node<T> node) {
        T value = null;
        if (node.numberOfKeys() > 0) {
            value = node.removeKey(node.numberOfKeys() - 1);
        }
        return value;
    }

    @Override
    public void clear() {
        root = null;
        size = 0;
    }

    @Override
    public boolean contains(T value) {
        Node<T> node = getNode(value);
        return (node != null);
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public Collection<T> toCollection() {
        return (new JavaCompatibleBTree<T>(this));
    }

    @Override
    public boolean validate() {
        if (root == null) return true;
        return validateNode(root);
    }

    /**
     * Validate the node according to the B-Tree invariants.
     *
     * @param node
     *            to validate.
     * @return True if valid.
     */
    private boolean validateNode(Node<T> node) {
        int keySize = node.numberOfKeys();
        if (keySize > 1) {
            // Make sure the keys are sorted
            for (int i = 1; i < keySize; i++) {
                T p = node.getKey(i - 1);
                T n = node.getKey(i);
                if (p.compareTo(n) > 0)
                    return false;
            }
        }
        int childrenSize = node.numberOfChildren();
        if (node.parent == null) {
            // root
            if (keySize > maxKeySize) {
                // check max key size. root does not have a min key size
                return false;
            } else if (childrenSize == 0) {
                // if root, no children, and keys are valid
                return true;
            } else if (childrenSize < 2) {
                // root should have zero or at least two children
                return false;
            } else if (childrenSize > maxChildrenSize) {
                return false;
            }
        } else {
            // non-root
            if (keySize < minKeySize) {
                return false;
            } else if (keySize > maxKeySize) {
                return false;
            } else if (childrenSize == 0) {
                return true;
            } else if (keySize != (childrenSize - 1)) {
                // If there are chilren, there should be one more child then
                // keys
                return false;
            } else if (childrenSize < minChildrenSize) {
                return false;
            } else if (childrenSize > maxChildrenSize) {
                return false;
            }
        }

        Node<T> first = node.getChild(0);
        // The first child's last key should be less than the node's first key
        if (first.getKey(first.numberOfKeys() - 1).compareTo(node.getKey(0)) > 0)
            return false;

        Node<T> last = node.getChild(node.numberOfChildren() - 1);
        // The last child's first key should be greater than the node's last key
        if (last.getKey(0).compareTo(node.getKey(node.numberOfKeys() - 1)) < 0)
            return false;

        // Check that each node's first and last key holds it's invariance
        for (int i = 1; i < node.numberOfKeys(); i++) {
            T p = node.getKey(i - 1);
            T n = node.getKey(i);
            Node<T> c = node.getChild(i);
            if (p.compareTo(c.getKey(0)) > 0)
                return false;
            if (n.compareTo(c.getKey(c.numberOfKeys() - 1)) < 0)
                return false;
        }

        for (int i = 0; i < node.childrenSize; i++) {
            Node<T> c = node.getChild(i);
            boolean valid = this.validateNode(c);
            if (!valid)
                return false;
        }

        return true;
    }

    private Node<T> getNode(T value) {
        Node<T> node = root;
        while (node != null) {
            T lesser = node.getKey(0);
            if (value.compareTo(lesser) < 0) {
                if (node.numberOfChildren() > 0)
                    node = node.getChild(0);
                else
                    node = null;
                continue;
            }

            int numberOfKeys = node.numberOfKeys();
            int last = numberOfKeys - 1;
            T greater = node.getKey(last);
            if (value.compareTo(greater) > 0) {
                if (node.numberOfChildren() > numberOfKeys)
                    node = node.getChild(numberOfKeys);
                else
                    node = null;
                continue;
            }

            for (int i = 0; i < numberOfKeys; i++) {
                T currentValue = node.getKey(i);
                if (currentValue.compareTo(value) == 0) {
                    return node;
                }

                int next = i + 1;
                if (next <= last) {
                    T nextValue = node.getKey(next);
                    if (currentValue.compareTo(value) < 0 && nextValue.compareTo(value) > 0) {
                        if (next < node.numberOfChildren()) {
                            node = node.getChild(next);
                            break;
                        }
                        return null;
                    }
                }
            }
        }
        return null;
    }

    private static class Node<T extends Comparable<T>> {

        private T[] keys = null;
        private int keysSize = 0;
        private Node<T>[] children = null;
        private int childrenSize = 0;
        private Comparator<Node<T>> comparator = new Comparator<Node<T>>() {
            @Override
            public int compare(Node<T> arg0, Node<T> arg1) {
                return arg0.getKey(0).compareTo(arg1.getKey(0));
            }
        };

        protected Node<T> parent = null;

        private Node(Node<T> parent, int maxKeySize, int maxChildrenSize) {
            this.parent = parent;
            this.keys = (T[]) new Comparable[maxKeySize + 1];
            this.keysSize = 0;
            this.children = new Node[maxChildrenSize + 1];
            this.childrenSize = 0;
        }

        private T getKey(int index) {
            return keys[index];
        }

        private int indexOf(T value) {
            for (int i = 0; i < keysSize; i++) {
                if (keys[i].equals(value)) return i;
            }
            return -1;
        }

        private void addKey(T value) {
            keys[keysSize++] = value;
            Arrays.sort(keys, 0, keysSize);
        }

        private T removeKey(T value) {
            T removed = null;
            boolean found = false;
            if (keysSize == 0) return null;
            for (int i = 0; i < keysSize; i++) {
                if (keys[i].equals(value)) {
                    found = true;
                    removed = keys[i];
                } else if (found) {
                    // shift the rest of the keys down
                    keys[i - 1] = keys[i];
                }
            }
            if (found) {
                keysSize--;
                keys[keysSize] = null;
            }
            return removed;
        }

        private T removeKey(int index) {
            if (index >= keysSize)
                return null;
            T value = keys[index];
            for (int i = index + 1; i < keysSize; i++) {
                // shift the rest of the keys down
                keys[i - 1] = keys[i];
            }
            keysSize--;
            keys[keysSize] = null;
            return value;
        }

        private int numberOfKeys() {
            return keysSize;
        }

        private Node<T> getChild(int index) {
            if (index >= childrenSize)
                return null;
            return children[index];
        }

        private int indexOf(Node<T> child) {
            for (int i = 0; i < childrenSize; i++) {
                if (children[i].equals(child))
                    return i;
            }
            return -1;
        }

        private boolean addChild(Node<T> child) {
            child.parent = this;
            children[childrenSize++] = child;
            Arrays.sort(children, 0, childrenSize, comparator);
            return true;
        }

        private boolean removeChild(Node<T> child) {
            boolean found = false;
            if (childrenSize == 0)
                return found;
            for (int i = 0; i < childrenSize; i++) {
                if (children[i].equals(child)) {
                    found = true;
                } else if (found) {
                    // shift the rest of the keys down
                    children[i - 1] = children[i];
                }
            }
            if (found) {
                childrenSize--;
                children[childrenSize] = null;
            }
            return found;
        }

        private Node<T> removeChild(int index) {
            if (index >= childrenSize)
                return null;
            Node<T> value = children[index];
            children[index] = null;
            for (int i = index + 1; i < childrenSize; i++) {
                // shift the rest of the keys down
                children[i - 1] = children[i];
            }
            childrenSize--;
            children[childrenSize] = null;
            return value;
        }

        private int numberOfChildren() {
            return childrenSize;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();

            builder.append("keys=[");
            for (int i = 0; i < numberOfKeys(); i++) {
                T value = getKey(i);
                builder.append(value);
                if (i < numberOfKeys() - 1)
                    builder.append(", ");
            }
            builder.append("]\n");

            if (parent != null) {
                builder.append("parent=[");
                for (int i = 0; i < parent.numberOfKeys(); i++) {
                    T value = parent.getKey(i);
                    builder.append(value);
                    if (i < parent.numberOfKeys() - 1)
                        builder.append(", ");
                }
                builder.append("]\n");
            }

            if (children != null) {
                builder.append("keySize=").append(numberOfKeys()).append(" children=").append(numberOfChildren()).append("\n");
            }

            return builder.toString();
        }
    }

    private static class TreePrinter {

        public static <T extends Comparable<T>> String getString(BTree<T> tree) {
            if (tree.root == null) return "Tree has no nodes.";
            return getString(tree.root, "", true);
        }

        private static <T extends Comparable<T>> String getString(Node<T> node, String prefix, boolean isTail) {
            StringBuilder builder = new StringBuilder();

            builder.append(prefix).append((isTail ? "└── " : "├── "));
            for (int i = 0; i < node.numberOfKeys(); i++) {
                T value = node.getKey(i);
                builder.append(value);
                if (i < node.numberOfKeys() - 1)
                    builder.append(", ");
            }
            builder.append("\n");

            if (node.children != null) {
                for (int i = 0; i < node.numberOfChildren() - 1; i++) {
                    Node<T> obj = node.getChild(i);
                    builder.append(getString(obj, prefix + (isTail ? "    " : "│   "), false));
                }
                if (node.numberOfChildren() >= 1) {
                    Node<T> obj = node.getChild(node.numberOfChildren() - 1);
                    builder.append(getString(obj, prefix + (isTail ? "    " : "│   "), true));
                }
            }

            return builder.toString();
        }
    }

    public static class JavaCompatibleBTree<T extends Comparable<T>> extends java.util.AbstractCollection<T> {

        private BTree<T> tree = null;

        public JavaCompatibleBTree(BTree<T> tree) {
            this.tree = tree;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean add(T value) {
            return tree.add(value);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean remove(Object value) {
            return (tree.remove((T)value)!=null);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean contains(Object value) {
            return tree.contains((T)value);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int size() {
            return tree.size();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public java.util.Iterator<T> iterator() {
            return (new BTreeIterator<T>(this.tree));
        }

        private static class BTreeIterator<C extends Comparable<C>> implements java.util.Iterator<C> {

            private BTree<C> tree = null;
            private BTree.Node<C> lastNode = null;
            private C lastValue = null;
            private int index = 0;
            private Deque<Node<C>> toVisit = new ArrayDeque<Node<C>>();

            protected BTreeIterator(BTree<C> tree) {
                this.tree = tree;
                if (tree.root!=null && tree.root.keysSize>0) {
                    toVisit.add(tree.root);
                }
            }

            /**
             * {@inheritDoc}
             */
            @Override
            public boolean hasNext() {
                if ((lastNode!=null && index<lastNode.keysSize)||(toVisit.size()>0)) return true;
                return false;
            }

            /**
             * {@inheritDoc}
             */
            @Override
            public C next() {
                if (lastNode!=null && (index < lastNode.keysSize)) {
                    lastValue = lastNode.getKey(index++);
                    return lastValue;
                }
                while (toVisit.size()>0) {
                    // Go thru the current nodes
                    BTree.Node<C> n = toVisit.pop();

                    // Add non-null children
                    for (int i=0; i<n.childrenSize; i++) {
                        toVisit.add(n.getChild(i));
                    }

                    // Update last node (used in remove method)
                    index = 0;
                    lastNode = n;
                    lastValue = lastNode.getKey(index++);
                    return lastValue;
                }
                return null;
            }

            /**
             * {@inheritDoc}
             */
            @Override
            public void remove() {
                if (lastNode!=null && lastValue!=null) {
                    // On remove, reset the iterator (very inefficient, I know)
                    tree.remove(lastValue,lastNode);

                    lastNode = null;
                    lastValue = null;
                    index = 0;
                    toVisit.clear();
                    if (tree.root!=null && tree.root.keysSize>0) {
                        toVisit.add(tree.root);
                    }
                }
            }
        }
    }
}
