#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <seal/seal.h>
#include <pthread.h>
#include <unistd.h>
#include <chrono>
#include <memory>
#include <random>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sstream>
#include <mutex>

using namespace std::chrono;
using namespace std;
using namespace seal;
std :: mutex m;
bool onetime = false;
int countThread = 0;
auto start = chrono::high_resolution_clock::now();

void SealPIR(uint64_t number_of_items, uint64_t size_per_item, uint32_t N, uint32_t logt, uint32_t d, int size_db, int opt) {

  EncryptionParameters params(scheme_type::BFV);
  PirParams pir_params;

  gen_params(number_of_items, size_per_item, N, logt, d, params, pir_params);
  // Initialize PIR server....
  PIRServer server(params, pir_params);

  // Initialize PIR client....
  PIRClient client(params, pir_params);
  GaloisKeys galois_keys = client.generate_galois_keys();

  server.set_galois_key(0, galois_keys);

  // Create test database
  auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

  // Copy of the database. We use this at the end to make sure we retrieved
  // the correct element.
  auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));

  random_device rd;
  for (uint64_t i = 0; i < number_of_items; i++) {
      for (uint64_t j = 0; j < size_per_item; j++) {
          auto val = rd() % 256;
          db.get()[(i * size_per_item) + j] = val;
          db_copy.get()[(i * size_per_item) + j] = val;
      }
  }

  // Measure database setup
  server.set_database(move(db), number_of_items, size_per_item);
  server.preprocess_database();

  // Choose an index of an element in the DB
  //random_device rd;
  uint64_t ele_index = rd() % number_of_items; // element in DB at random position
  //uint64_t ele_index = 2;
  //cout << "Main: element index: " << ele_index << endl;
  uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
  uint64_t offset = client.get_fv_offset(ele_index, size_per_item); // offset in FV plaintext

  //Lock to wait other threads finish
  m.lock();
  if (!onetime){
    onetime = true;
    cout << endl;
    cout << "Waitting other threads before continuing..." << endl;
    cout << endl;
    if (opt == 2){
      sleep(size_db*5);
    }
    else {
      sleep(10);
    }
    start = chrono::high_resolution_clock::now();
  }
  m.unlock();

  // Measure query generation
  PirQuery query = client.generate_query(index);
  // Measure query processing (including expansion)
  PirReply reply = server.generate_reply(query, 0);
  // Measure response extraction
  Plaintext result = client.decode_reply(reply);

  countThread++;
  if (countThread == size_db){
    auto end = chrono::high_resolution_clock::now();
    auto total = duration_cast<microseconds>(end - start).count();
    cout << "Total SEALPIR time: " << total / 1000 << " ms" << endl;
    onetime = false;
    countThread = 0;
  }

  // Convert from FV plaintext (polynomial) to database element at the client
  vector<uint8_t> elems(N * logt / 8);
  coeffs_to_bytes(logt, result, elems.data(), (N * logt) / 8);

  // Check that we retrieved the correct element
  for (uint32_t i = 0; i < size_per_item; i++) {
      //cout << "Main: Result i = " << i << " elems = " << (int)db_copy.get()[(ele_index * size_per_item) + i] << " size = " << (ele_index * size_per_item) + i << endl;
      if (elems[(offset * size_per_item) + i] != db_copy.get()[(ele_index * size_per_item) + i]) {
          cout << "Main: elems " << (int)elems[(offset * size_per_item) + i] << ", db "
              << (int) db_copy.get()[(ele_index * size_per_item) + i] << endl;
          cout << "Main: PIR result wrong!" << endl;
        }
  }
  // Output results
  cout << "Main: PIR result correct!" << endl;
}

int main(int argc, char *argv[]) {
  while(1){
    int n_db;
    int solution;
    cout << "***** Menu - Parallel *****"<< endl;
    cout << "1. Call SealPIR on the whole tree - O(2n)"<< endl;
    cout << "2. Call SealPIR on each layer and wait for the slowest - (O(n))"<< endl;
    cout << "3. Call SealPIR on balanced partition - O(n/logn)"<< endl;
    cout << "4. End"<< endl;
    cout << "Choose your solutions from 1 to 3:  ";
    cin >> solution; // Get user input from the keyboard
    cout << "Type a size of database: 2^"; // Type a number and press enter
    cin >> n_db; // Get user input from the keyboard

    //size of database - number of transactions (n)
    uint64_t n = 1 << n_db;
    //size of hash value
    uint64_t size_per_item = 32; //in bytes
    //degree of polynomial
    uint32_t N = 2048;

    // Recommended values: (logt, d) = (12, 2) or (8, 1).
    uint32_t logt = 12;
    uint32_t d = 2;

    //3. Call SealPIR on balanced partition - O(n/logn)
    if(solution == 3){
      //partition size ((2*n-2)/log(n))
      uint64_t number_of_items = ceil((2*n - 2)/n_db);
      //parallel
      vector<thread> threads;
      for (int i = 0; i < n_db; i++) {
        threads.push_back(thread(SealPIR, number_of_items, size_per_item, N, logt, d, n_db, solution));
      }
      for (auto &th : threads) {
        th.join();
      }
    }
    //2. Call SealPIR on each layer and wait for the slowest - (O(n))
    else if(solution == 2){
      //parallel
      vector<thread> threads;
      for (uint64_t i = n_db; i > 0; i--) {
          uint64_t number_of_items = 1 << i;
          threads.push_back(thread(SealPIR, number_of_items, size_per_item, N, logt, d, n_db, solution));
      }
      for (auto &th : threads) {
        th.join();
      }
    }
    //1. Call SealPIR on the whole tree - O(2n)
    else if(solution == 1){
      uint64_t number_of_items = (2*n - 1);
      //parallel
      vector<thread> threads;
      for (int i = 0; i < n_db; i++) {
        threads.push_back(thread(SealPIR, number_of_items, size_per_item, N, logt, d, n_db, solution));
      }
      for (auto &th : threads) {
        th.join();
      }
    }
    else {
      break;
    }
  }
  return 0;
}
