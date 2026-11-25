# Design and Analysis of Algorithms (DAA) Lab

Welcome to the **Design and Analysis of Algorithms (DAA)** laboratory program repository. This workspace contains Python implementations of core algorithms covering searching, string matching, greedy minimum spanning trees, and single-source shortest paths. 

Each program features rigorous implementation along with comparative performance analysis (timing and operation/comparison counts) to demonstrate empirical time complexities.

---

## 📂 Repository Structure

| Experiment / Program | Description | Key Algorithms |
| :--- | :--- | :--- |
| **[1: interpolation_vs_binary_search.py](file:///run/media/kishore/Data/SEM%20-%203/1lab/DAA/Program/1:%20interpolation_vs_binary_search.py)** | Comparison of logarithmic searching techniques. | Binary Search, Interpolation Search |
| **[2: string_matching_comparison.py](file:///run/media/kishore/Data/SEM%20-%203/1lab/DAA/Program/2:%20string_matching_comparison.py)** | Evaluates pattern searching algorithms on comparison count. | Naive Search, KMP Search, Rabin-Karp |
| **[3: mst_kruskal_prim.py](file:///run/media/kishore/Data/SEM%20-%203/1lab/DAA/Program/3:%20mst_kruskal_prim.py)** | Finds Minimum Spanning Trees (MST) on undirected graphs. | Kruskal's (Union-Find), Prim's (Min-Heap) |
| **[4: dijkstra_shortest_path.py](file:///run/media/kishore/Data/SEM%20-%203/1lab/DAA/Program/4:%20dijkstra_shortest_path.py)** | Solves Single-Source Shortest Paths (SSSP) problems. | Dijkstra's Algorithm (Min-Heap) |

---

## 🛠️ Program Details & Theoretical Analysis

### 1. Interpolation vs. Binary Search
Located in: [1: interpolation_vs_binary_search.py](file:///run/media/kishore/Data/SEM%20-%203/1lab/DAA/Program/1:%20interpolation_vs_binary_search.py)

This program compares two searching algorithms on sorted, uniformly distributed datasets of varying sizes ($10^3$ to $10^5$ items).
* **Binary Search**: Dividends the search space by half. 
  * *Time Complexity*: $\mathcal{O}(\log n)$ (Best/Average/Worst Case)
  * *Space Complexity*: $\mathcal{O}(1)$
* **Interpolation Search**: Estimates the position of the target using a linear interpolation formula:
  $$\text{pos} = \text{low} + \left\lfloor \frac{(\text{target} - \text{arr}[\text{low}]) \cdot (\text{high} - \text{low})}{\text{arr}[\text{high}] - \text{arr}[\text{low}]} \right\rfloor$$
  * *Time Complexity*: $\mathcal{O}(\log \log n)$ average case (on uniformly distributed data), $\mathcal{O}(n)$ worst case.
  * *Space Complexity*: $\mathcal{O}(1)$

### 2. String Matching Comparison
Located in: [2: string_matching_comparison.py](file:///run/media/kishore/Data/SEM%20-%203/1lab/DAA/Program/2:%20string_matching_comparison.py)

Compares string matching paradigms on a large string text ($10^4$ characters) across various pattern lengths:
* **Naive Search**: Slides the pattern over the text and compares character-by-character.
  * *Time Complexity*: $\mathcal{O}((n-m+1) \cdot m)$ worst case.
* **Knuth-Morris-Pratt (KMP)**: Utilizes a pre-computed Longest Prefix Suffix (LPS) table to skip redundant character comparisons.
  * *Time Complexity*: $\mathcal{O}(n + m)$ preprocessing and matching time.
* **Rabin-Karp**: Computes hash values of the pattern and text substrings using rolling hash logic. On hash matches, it falls back to character comparisons.
  * *Time Complexity*: $\mathcal{O}(n + m)$ average/best case, $\mathcal{O}(n \cdot m)$ worst case.

### 3. Minimum Spanning Tree (MST)
Located in: [3: mst_kruskal_prim.py](file:///run/media/kishore/Data/SEM%20-%203/1lab/DAA/Program/3:%20mst_kruskal_prim.py)

Solves the Minimum Spanning Tree problem for connected, weighted undirected graphs using two greedy algorithms:
* **Kruskal's Algorithm**:
  * Employs an edge-centric greedy strategy. It sorts all edges and adds them to the tree unless it introduces a cycle.
  * Utilizes a [UnionFind](file:///run/media/kishore/Data/SEM%20-%203/1lab/DAA/Program/3:%20mst_kruskal_prim.py#L5) (Disjoint Set Union) class optimized with **Path Compression** and **Union by Rank**.
  * *Time Complexity*: $\mathcal{O}(E \log E)$ or $\mathcal{O}(E \log V)$
* **Prim's Algorithm**:
  * Employs a vertex-centric greedy strategy. Starts at a root vertex and grows the tree by adding the cheapest node connected to the existing MST.
  * Utilizes a priority queue via Python's `heapq` module.
  * *Time Complexity*: $\mathcal{O}(E \log V)$

### 4. Dijkstra's Shortest Path
Located in: [4: dijkstra_shortest_path.py](file:///run/media/kishore/Data/SEM%20-%203/1lab/DAA/Program/4:%20dijkstra_shortest_path.py)

Implements the single-source shortest path algorithm on a weighted directed graph where edges are non-negative.
* Uses an adjacency list representation of the graph.
* Employs a Min-Heap (`heapq` priority queue) to retrieve the node with the minimum distance at each step.
* Tracks parent linkages to reconstruct the actual path from the source node to any reachable node using the `reconstruct_path` function.
* *Time Complexity*: $\mathcal{O}((V + E) \log V)$
* *Space Complexity*: $\mathcal{O}(V)$ for structures (distances, visited set, priority queue).

---

## 🚀 How to Run the Programs

All scripts are written in standard Python 3 and require no external dependencies outside the standard library.

1. **Clone/Navigate** to your workspace folder:
   ```bash
   cd "/run/media/kishore/Data/SEM - 3/1lab/DAA/Program"
   ```

2. **Execute** any script using Python:
   * **Interpolation vs Binary Search**:
     ```bash
     python3 "1: interpolation_vs_binary_search.py"
     ```
   * **String Matching Comparison**:
     ```bash
     python3 "2: string_matching_comparison.py"
     ```
   * **MST (Kruskal & Prim)**:
     ```bash
     python3 "3: mst_kruskal_prim.py"
     ```
   * **Dijkstra's Shortest Path**:
     ```bash
     python3 "4: dijkstra_shortest_path.py"
     ```

---

## 📈 Learning Takeaways
* **Algorithm Selection**: Choice of algorithms depends heavily on input distribution (e.g., Interpolation Search dominates Binary Search when inputs are sorted and uniformly distributed).
* **Data Structures**: Using efficient data structures such as Priority Queues (via `heapq`) and Union-Find disjoint sets transforms the asymptotic running times of graph algorithms from quadratic ($\mathcal{O}(V^2)$) to logarithmic-product scales ($\mathcal{O}(E \log V)$).
* **String Processing**: KMP and Rabin-Karp illustrate how mathematical insights (prefix analysis & modular hashes) prevent repetitive scan loops.
