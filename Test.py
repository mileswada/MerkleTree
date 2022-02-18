from opcode import haslocal
from random import random
from Merkle import MerkleTree, MerkleNode, verify_proof_of_inclusion
import hashlib
import random

def test_simple():
    mt = MerkleTree()
    mt.add_node('skldfj')
    mt.add_node('skldfjas')
    mt.add_node('iowhegoiaw')
    mt.add_node('askdlg')
    mt.add_node('hilkjsdf')
    
    pi = mt.generate_proof_of_inclusion('skldfj')
    assert(verify_proof_of_inclusion('skldfj', pi))

    pi = mt.generate_proof_of_inclusion('skldfjas')
    assert(verify_proof_of_inclusion('skldfjas', pi))

    pi = mt.generate_proof_of_inclusion('iowhegoiaw')
    assert(verify_proof_of_inclusion('iowhegoiaw', pi))
    
    pi = mt.generate_proof_of_inclusion('askdlg')
    assert(verify_proof_of_inclusion('askdlg', pi))

    pi = mt.generate_proof_of_inclusion('hilkjsdf')
    assert(verify_proof_of_inclusion('hilkjsdf', pi))

def test_interleaved_queries():
    mt = MerkleTree()

    h = hashlib.new('sha256')
    h.update(("Alice_decryption_attempt" + str(random.random())).encode('utf-8'))
    message1 = h.hexdigest()
    mt.add_node(message1)

    pi = mt.generate_proof_of_inclusion(message1)
    assert(verify_proof_of_inclusion(message1, pi))

    # Add some miscellaneous nodes to the tree
    mt.add_node('23oih389ahsjdklngjoa9087wo3tankgi8ao2uhtkdsjljsdukjsdhfgalsdiu23azo8ai')
    mt.add_node('ash9308yahwuoiojua8sy97fgybh2aseio9wuagalksoeihg39a0seigd3i9r83jnldjpf')
    mt.add_node('q89whougikjosadiuygukhjwk3uit8qpuhadsglgqpjbasdfg9gNfglja376atyfsgdhvb')
    mt.add_node('9na398abw738cv9wb3oybdfc0qw03cbadsbcy938casbdlckashdfacsdb9w3btlacs888')
    mt.add_node('aopw9e08hg7uaindosklgjhasugehbjntjoqhwguiebnkmladjoihg8w39tw0hojhbkajo')

    h = hashlib.new('sha256')
    h.update(("Bob_decryption_attempt" + str(random.random())).encode('utf-8'))
    message2 = h.hexdigest()
    mt.add_node(message2)

    pi = mt.generate_proof_of_inclusion(message2)
    assert(verify_proof_of_inclusion(message2, pi))

    h = hashlib.new('sha256')
    h.update(("Alice_second_decryption_attempt" + str(random.random())).encode('utf-8'))
    message3 = h.hexdigest()
    mt.add_node(message3)

    pi = mt.generate_proof_of_inclusion(message3)
    assert(verify_proof_of_inclusion(message3, pi))

    # Verify that Bob's and Alice's entries in the tree are still present
    pi = mt.generate_proof_of_inclusion(message1)
    assert(verify_proof_of_inclusion(message1, pi))

    pi = mt.generate_proof_of_inclusion(message2)
    assert(verify_proof_of_inclusion(message2, pi))


def test_false_proof():
    mt = MerkleTree()

    h = hashlib.new('sha256')
    h.update(("Alice_decryption_attempt" + str(random.random())).encode('utf-8'))
    message1 = h.hexdigest()
    mt.add_node(message1)

    pi = mt.generate_proof_of_inclusion(message1)
    assert(verify_proof_of_inclusion(message1, pi))

    # Add some miscellaneous nodes to the tree
    mt.add_node('9na398abw738cv9wb3oybdfc0qw03cbadsbcy938casbdlckashdfacsdb9w3btlacs888')
    mt.add_node('aopw9e08hg7uaindosklgjhasugehbjntjoqhwguiebnkmladjoihg8w39tw0hojhbkajo')

    h = hashlib.new('sha256')
    h.update(("Bob_decryption_attempt" + str(random.random())).encode('utf-8'))
    message2 = h.hexdigest()
    mt.add_node(message2)

    # Modify proof of inclusion to be incorrect
    pi = mt.generate_proof_of_inclusion(message2)
    pi[2] += 'temp'
    assert(not verify_proof_of_inclusion(message2, pi))

    # Modify root of the tree and confirm that all proofs of inclusion will fail
    mt.root.hash += 'malicious action'

    pi = mt.generate_proof_of_inclusion(message1)
    assert(not verify_proof_of_inclusion(message1, pi))


def test_large():
    mt = MerkleTree()
    num_entries = 100000

    for i in range(num_entries):
        h = hashlib.new('sha256')
        h.update(("Entry " + str(i)).encode('utf-8'))
        message = h.hexdigest()
        mt.add_node(message)
    
    assert(mt.size == num_entries)

    for _ in range(1000):
        random_index = random.randint(0, num_entries)
        h = hashlib.new('sha256')
        h.update(("Entry " + str(random_index)).encode('utf-8'))
        message = h.hexdigest()
        
        pi = mt.generate_proof_of_inclusion(message)
        assert(verify_proof_of_inclusion(message, pi))



test_simple()
test_interleaved_queries()
test_false_proof()
test_large()

print("All tests passed.")


