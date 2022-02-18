import hashlib

class MerkleNode:
    def __init__(self, left=None, right=None, parent=None, hash='0') -> None:
        """ HASH should be a string produced by a call to hexdigest(). """

        self.left = left
        self.right = right
        self.parent = parent
        self.hash = hash

    def update_hash(self):
        # Ensure a leaf node cannot call this function
        if self.left == self.right == None:
            print("leaf node called update_hash when it shouldn't have.")
            return
        
        h = hashlib.new('sha256')

        if self.left != None:
            h.update(self.left.hash.encode('utf-8'))
            
        if self.right != None:
            h.update(self.right.hash.encode('utf-8'))

        self.hash = h.hexdigest()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, MerkleNode) and self.hash == other.hash
    
    def __hash__(self) -> int:
        return hash((self.hash))
    
    def display(self):
        lines, *_ = self._display_aux()
        for line in lines:
            print(line)

    def _display_aux(self):
        """Returns list of strings, width, height, and horizontal coordinate of the root."""
        # No child.
        if self.right is None and self.left is None:
            line = '%s' % self.hash[:10]
            width = len(line)
            height = 1
            middle = width // 2
            return [line], width, height, middle

        # Only left child.
        if self.right is None:
            lines, n, p, x = self.left._display_aux()
            s = '%s' % self.hash[:10]
            u = len(s)
            first_line = (x + 1) * ' ' + (n - x - 1) * '_' + s
            second_line = x * ' ' + '/' + (n - x - 1 + u) * ' '
            shifted_lines = [line + u * ' ' for line in lines]
            return [first_line, second_line] + shifted_lines, n + u, p + 2, n + u // 2

        # Only right child.
        if self.left is None:
            lines, n, p, x = self.right._display_aux()
            s = '%s' % self.hash[:10]
            u = len(s)
            first_line = s + x * '_' + (n - x) * ' '
            second_line = (u + x) * ' ' + '\\' + (n - x - 1) * ' '
            shifted_lines = [u * ' ' + line for line in lines]
            return [first_line, second_line] + shifted_lines, n + u, p + 2, u // 2

        # Two children.
        left, n, p, x = self.left._display_aux()
        right, m, q, y = self.right._display_aux()
        s = '%s' % self.hash[:10]
        u = len(s)
        first_line = (x + 1) * ' ' + (n - x - 1) * '_' + s + y * '_' + (m - y) * ' '
        second_line = x * ' ' + '/' + (n - x - 1 + u + y) * ' ' + '\\' + (m - y - 1) * ' '
        if p < q:
            left += [n * ' '] * (q - p)
        elif q < p:
            right += [m * ' '] * (p - q)
        zipped_lines = zip(left, right)
        lines = [first_line, second_line] + [a + u * ' ' + b for a, b in zipped_lines]
        return lines, n + m + u, max(p, q) + 2, n + u // 2


class MerkleTree:

    def __init__(self) -> None:
        self.size = 0 # Number of entries in the Merkle Tree. (which equals # of leaf nodes)
        self.depth = 2 # Depth that the Merkle Tree can currently support
        self.root = MerkleNode()
        self.to_be_parents = [self.root] # Future parents of new Merkle leaves created by add_node
        self.leaves = {} # Dictionary of all entries in the Merkle Log. (Entries are mapped to themselves)


    def add_node(self, message_digest):
        """ Add a leaf node containing MESSAGE_DIGEST to the tree. 
            Should increase the depth of the tree if the tree is full. 
        """

        self.size += 1

        # If we've exceeded the leaf node capacity, expand the tree
        if len(self.to_be_parents) == 0:
            new_root = MerkleNode(left=self.root)
            
            new_root.left = self.root
            new_root.right = self.__create_empty_tree(self.depth - 1)
            assert(len(self.to_be_parents) == 2 ** (self.depth - 2))
            
            new_root.right.parent = new_root
            self.root.parent = new_root
            
            self.root = new_root
            self.depth += 1



        # Create a new MerkleNode containing MESSAGE_DIGEST and add it to the tree
        parent_node = self.to_be_parents[0]
        new_node = MerkleNode(parent=parent_node, hash=message_digest)
        self.leaves[new_node] = new_node

        if parent_node.left == None:
            parent_node.left = new_node
        else:
            parent_node.right = new_node
            self.to_be_parents.pop(0)

        # Update intermediary Merkle nodes on upward path
        temp_node = parent_node
        while temp_node != None:
            temp_node.update_hash()
            temp_node = temp_node.parent


    def __create_empty_tree(self, depth):
        """ Create a complete Merkle Tree of depth DEPTH. Add the newly created leaves of this 
            tree to toBeParents. 
        """
        empty_tree_root = MerkleNode()

        if depth > 1:
            empty_tree_root.left = self.__create_empty_tree_helper(depth - 1, empty_tree_root)
            empty_tree_root.right = self.__create_empty_tree_helper(depth - 1, empty_tree_root)
        elif depth == 1:
            self.to_be_parents.append(empty_tree_root)

        return empty_tree_root


    def __create_empty_tree_helper(self, d, parent_node):
        new_node = MerkleNode(parent=parent_node)

        # If d == 1, then we've created a leaf and thus append the leaf to to_be_parents
        if d <= 1:
            self.to_be_parents.append(new_node)
        
        # Otherwise, continue recursively in preorder fashion
        else:
            new_node.left = self.__create_empty_tree_helper(d - 1, new_node)
            
            new_node.right = self.__create_empty_tree_helper(d - 1, new_node)

        return new_node


    def generate_proof_of_inclusion(self, message_digest):
        """ Generate a proof of inclusion for the leaf node containing MESSAGE_DIGEST. """
        
        starting_node = MerkleNode(hash=message_digest)
        if starting_node in self.leaves:
            starting_node = self.leaves[starting_node]
        else:
            print("Entry corresponding to {0} not found in Merkle tree.".format((message_digest)))
            return []
        
        pi = []

        temp_node = starting_node
        while temp_node.parent != None:

            if temp_node.parent.left == temp_node:
                
                if temp_node.parent.right != None:
                    pi.append("R" + temp_node.parent.right.hash)
                else:
                    pi.append(None)
            
            elif temp_node.parent.right == temp_node:
                pi.append("L" + temp_node.parent.left.hash)

            temp_node = temp_node.parent
        
        pi.append(self.root.hash)

        return pi


def verify_proof_of_inclusion(message_digest, pi):
    """ Validate a Merkle proof of inclusion on MESSAGE_DIGEST given the co-path PI. """

    temp_hash = message_digest
    commitment = pi[len(pi) - 1]

    for i in range(len(pi) - 1):
        h = hashlib.new('sha256')

        if pi[i] == None:
            h.update(temp_hash.encode('utf-8'))
        elif pi[i][0] == 'R':
            h.update(temp_hash.encode('utf-8'))
            h.update(pi[i][1:].encode('utf-8'))
        elif pi[i][0] == 'L':
            h.update(pi[i][1:].encode('utf-8'))
            h.update(temp_hash.encode('utf-8'))
        else:
            print("Formatting error in co-path.")
            return False

        temp_hash = h.hexdigest()

    return temp_hash == commitment