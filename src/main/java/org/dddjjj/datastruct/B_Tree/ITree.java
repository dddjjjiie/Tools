package org.dddjjj.datastruct.B_Tree;

import java.util.Collection;

public interface ITree<T> {

    public boolean add(T value);

    public T remove(T value);

    public void clear();

    public boolean contains(T value);

    public int size();

    public boolean validate();

    public Collection<T> toCollection();
}
