import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.Spliterator;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.swing.JComponent;

import org.bouncycastle.util.Arrays;
import org.jgrapht.graph.AbstractBaseGraph;
import org.jgrapht.graph.DefaultGraphType;

import docking.ComponentProvider;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.service.graph.Attributed;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.EmptyGraphType;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphType;


public class CollectionDetection extends GhidraScript {

    private Program program;
    private PluginTool pluginTool;
    private AddressFactory addressFactory;
    private ReferenceManager referenceManager;

    private AttributedGraph memoryGraph;
    private AttributedGraph filteredGraph;


    @Override
    @SuppressWarnings("deprecation")
    public void run() throws Exception {
        this.program = currentProgram;
        this.pluginTool = getState().getTool();
        this.addressFactory = this.program.getAddressFactory();
        this.referenceManager = this.program.getReferenceManager();

        List<Address> memoryAddresses = loadNonNullMemoryAddresses();
        Map<Address, List<Reference>> addressReferences = loadAddressReferences(memoryAddresses);
        Map<Address, Long> addressesTableSize = generateAddressesTableSize(addressReferences);
        Map<Address, MemoryStructure> memoryStructures = generateAddressesTableMap(addressesTableSize);

        this.memoryGraph = new AttributedGraph("Memory Graph", new EmptyGraphType());
        generateMemoryStructureGraph(memoryStructures, addressReferences);

        GraphDisplayBroker mgGraphService = this.pluginTool.getService(GraphDisplayBroker.class);
        GraphDisplay mgGraphDisplay = mgGraphService.getDefaultGraphDisplay(false, this.monitor);
        mgGraphDisplay.setGraph(this.memoryGraph, "Memory Graph", false, this.monitor);

        // There is code block with filtered child nodes.
        this.filteredGraph = new AttributedGraph("Filtered Graph", new EmptyGraphType());
        CustomAttributedGraph taintedGraph = transformGraphToTaintedGraph(this.memoryGraph);
        boolean isAcyclicGraph = isGeneratedGraphAcyclic(taintedGraph);
        findRootGraphNodes(taintedGraph);

        GraphDisplayBroker service = this.pluginTool.getService(GraphDisplayBroker.class);
        GraphDisplay display = service.getDefaultGraphDisplay(false, this.monitor);
        display.setGraph(this.filteredGraph, "Filtered Graph", false, this.monitor);
    }

    private List<Address> loadNonNullMemoryAddresses() {
        AddressIterator addressIterator = currentProgram.getMemory().getAddresses(true);
        return StreamSupport.stream(addressIterator.spliterator(), false)
                .sorted()
                .collect(Collectors.toList());
    }

    private Map<Address, List<Reference>> loadAddressReferences(List<Address> addresses) {
        Map<Address, List<Reference>> addressReferencess = addresses.stream()
                .collect(Collectors.toMap(addr -> addr, addr -> this.getPointerReferences(addr)))
                .entrySet()
                .stream()
                .filter(entry -> !entry.getValue().isEmpty())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        return addressReferencess;
    }

    private List<Reference> getPointerReferences(Address address) {
        List<Reference> availableReferences = new ArrayList<>();

        if (this.referenceManager.getReferenceCountTo(address) > 0) {
            ReferenceIterator refsIter = referenceManager.getReferencesTo(address);
            Spliterator<Reference> refsSpliter = refsIter.spliterator();
            List<Reference> references = StreamSupport.stream(refsSpliter, false)
                    .collect(Collectors.toList());

            availableReferences.addAll(references);
        }

        if (this.referenceManager.getReferenceCountFrom(address) > 0) {
            Reference[] refsArray = referenceManager.getReferencesFrom(address);
            List<Reference> references = List.of(refsArray);

            availableReferences.addAll(references);
        }

        return availableReferences;
    }

    private Map<Address, Long> generateAddressesTableSize(Map<Address, List<Reference>> addresses) {
        List<Address> toAddrsList = addresses.values()
                .stream()
                .flatMap(List::stream)
                .map(Reference::getToAddress)
                .sorted()
                .collect(Collectors.toList());

        Address prevAddr = toAddrsList.get(0);
        Map<Address, Long> tablesFrameSize = new HashMap<>();
        for (int i = 1; i < toAddrsList.size(); ++i) {
            Address currAddr = toAddrsList.get(i);
            Long addrsOffset = currAddr.getOffset() - prevAddr.getOffset() - 1;
            tablesFrameSize.put(prevAddr, (addrsOffset <= 128) ? addrsOffset : 128);

            prevAddr = currAddr;
        }

        tablesFrameSize.put(prevAddr, 128L);

        return tablesFrameSize;
    }

    private Map<Address, MemoryStructure> generateAddressesTableMap(Map<Address, Long> tablesFrameSize) {
        Map<Address, MemoryStructure> memStrctMap = new HashMap<>();
        for (Map.Entry<Address, Long> tableSizeEntry : tablesFrameSize.entrySet()) {
            Address startAddr = tableSizeEntry.getKey();
            Long endAddrOffset = startAddr.getOffset() + tableSizeEntry.getValue();

            AddressSpace currSpace = startAddr.getAddressSpace();
            Address endAddr = this.addressFactory.getAddress(currSpace.getSpaceID(), endAddrOffset);
            AddressSet tableSetAddrs = this.addressFactory.getAddressSet(startAddr, endAddr);

            memStrctMap.put(startAddr, new MemoryStructure(startAddr, tableSetAddrs));
        }

        return memStrctMap;
    }


    private void generateMemoryStructureGraph(Map<Address, MemoryStructure> memoryStructures, Map<Address, List<Reference>> references) {
        Set<Reference> referenceValues = references.values()
                .stream()
                .flatMap(List::stream)
                .collect(Collectors.toSet());

        Map<MemoryStructure, AttributedVertex> graphAttributes = memoryStructures.values()
                .stream()
                .collect(Collectors.toMap(strct -> strct, strct -> vertex(strct)));

        for (Reference currReference : referenceValues) {
            Address toAddress = currReference.getToAddress();
            Address fromAddress = currReference.getFromAddress();

            MemoryStructure toMemStrct = memoryStructures.get(toAddress);
            AttributedVertex toMemStrctVertex = graphAttributes.get(toMemStrct);

            Optional<MemoryStructure> optFromMemStrct = memoryStructures.values()
                    .stream()
                    .filter(strct -> strct.contains(fromAddress))
                    .findFirst();

            AttributedVertex fromMemStrctVertex = (optFromMemStrct.isPresent())
                    ? graphAttributes.get(optFromMemStrct.get()) : vertex(fromAddress);

            edge(fromMemStrctVertex, toMemStrctVertex);
        }
    }

    private AttributedVertex vertex(Address address) {
        String vertexLabel = String.format("0x%s", Long.toHexString(address.getOffset()));
        return this.memoryGraph.addVertex(vertexLabel, vertexLabel);
    }

    private AttributedVertex vertex(MemoryStructure memStructure) {
        String vertexLabel = String.format(
                "0x%s -> 0x%s\nAddress count: %s",
                Long.toHexString(memStructure.getStartAddress().getOffset()),
                Long.toHexString(memStructure.getLastAddress().getOffset()),
                memStructure.getAddressSetSize()
        );

        return this.memoryGraph.addVertex(vertexLabel, vertexLabel);

    }

    private AttributedEdge edge(AttributedVertex v1, AttributedVertex v2) {
        return this.memoryGraph.addEdge(v1, v2);
    }


    private CustomAttributedGraph transformGraphToTaintedGraph(AttributedGraph memGraph) {
        CustomAttributedGraph customGraph = new CustomAttributedGraph("Tainted Graph", new EmptyGraphType());
        memGraph.vertexSet().forEach(customGraph::addVertex);
        memGraph.edgeSet().forEach(nodeEdge -> {
            AttributedVertex srcVertex = memGraph.getEdgeSource(nodeEdge);
            AttributedVertex dstVertex = memGraph.getEdgeSource(nodeEdge);

            CustomAttributedVertex srcCustomVertex =
                    customGraph.addVertex(srcVertex.getId(), srcVertex.getName());

            CustomAttributedVertex dstCustomVertex =
                    customGraph.addVertex(dstVertex.getId(), dstVertex.getName());

            if (!customGraph.containsVertex(srcCustomVertex)) {
                customGraph.addVertex(srcCustomVertex);
            }

            if (!customGraph.containsVertex(dstCustomVertex)) {
                customGraph.addVertex(dstCustomVertex);
            }

            customGraph.addEdge(srcCustomVertex, dstCustomVertex);
        });

        return customGraph;
    }

    private boolean isGeneratedGraphAcyclic(CustomAttributedGraph customGraph) {
        // TODO: Improve the current algorithm to detect cycle only for parent nodes.
        Optional<CustomAttributedVertex> optCycleVertexes = customGraph.vertexSet()
                .stream()
                .filter(customGraph::hasCycle)
                .findAny();

        return optCycleVertexes.isEmpty();
    }

    private int findLinkedContainerRootNodes(AttributedGraph memoryGraph, int nodesCount) {

        boolean[] visited = new boolean[nodesCount];

        int v = 0;
//        for (int i = 0; i < nodesCount; i++) {
//            if (!visited[i]) {
//                DFS(memoryGraph, i, visited);
//                v = i;
//            }
//        }
//
//        Arrays.fill(visited, false);
//        DFS(memoryGraph, v, visited);
//
//        for (int i = 0; i < nodesCount; i++) {
//            if (!visited[i]) {
//                return -1;
//            }
//        }

        return v;
    }

//    private void DFS(AttributedGraph graph, int v, boolean[] discovered) {
//        discovered[v] = true;
//
//        for (int u: memoryGraph.adjList.get(v)) {
//            // `u` is not discovered
//            if (!discovered[u]) {
//                DFS(graph, u, discovered);
//            }
//        }
//    }


    private void findDoubleLinkedContainerRootNodes() {

    }

    private void generateAcyclicGraph() {

    }

    private void findRootGraphNodes(CustomAttributedGraph customGraph) {
        List<AttributedVertex> nonRootGraphNodes = new ArrayList<>();
        for (AttributedVertex graphNode : this.memoryGraph.vertexSet()) {
            Set<AttributedEdge> outGraphEdges = this.memoryGraph.outgoingEdgesOf(graphNode);
            if (outGraphEdges.isEmpty()) {
                nonRootGraphNodes.add(graphNode);
            }
        }

        for (AttributedVertex graphNode : this.memoryGraph.vertexSet()) {
            if (nonRootGraphNodes.contains(graphNode)) {
                continue;
            }

            this.filteredGraph.addVertex(graphNode);
            for (AttributedEdge graphNodeEdge : this.memoryGraph.outgoingEdgesOf(graphNode)) {
                AttributedVertex srcVertex = this.memoryGraph.getEdgeSource(graphNodeEdge);
                AttributedVertex dstVertex = this.memoryGraph.getEdgeTarget(graphNodeEdge);

                if (nonRootGraphNodes.contains(srcVertex) || nonRootGraphNodes.contains(dstVertex)) {
                    continue;
                }

                this.filteredGraph.addEdge(srcVertex, dstVertex);
            }
        }


    }

}


class CustomAttributedGraph extends AbstractBaseGraph<CustomAttributedVertex, AttributedEdge> {

    public static final String WEIGHT = "Weight";

    private String name;

    private GraphType type;

    private String description;

    private Map<String, CustomAttributedVertex> vertexMap = new HashMap<>();
    private final boolean collapseDuplicateEdges;


    public CustomAttributedGraph(String name, GraphType type) {
        this(name, type, name, true);
    }

    public CustomAttributedGraph(String name, GraphType type, String description) {
        this(name, type, description, true);
    }

    public CustomAttributedGraph(String name, GraphType type, String description, boolean collapseDuplicateEdges) {
        super(new VertexSupplier(), new EdgeSupplier(), DefaultGraphType.directedPseudograph());

        this.name = name;
        this.type = type;
        this.description = description;
        this.collapseDuplicateEdges = collapseDuplicateEdges;
    }


    public boolean hasCycle(CustomAttributedVertex sourceVertex) {
        sourceVertex.setBeingVisited(true);

        for (CustomAttributedVertex neighbor : sourceVertex.getAdjacencyList()) {
            if (neighbor.isBeingVisited()) {
                // backward edge exists
                return true;
            } else if (!neighbor.isVisited() && hasCycle(neighbor)) {
                return true;
            }
        }

        sourceVertex.setBeingVisited(false);
        sourceVertex.setVisited(true);
        return false;
    }


    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public GraphType getGraphType() {
        return type;
    }

    public CustomAttributedVertex addVertex(String id) {
        return addVertex(id, id);
    }

    public CustomAttributedVertex addVertex(String id, String vertexName) {
        if (vertexMap.containsKey(id)) {
            CustomAttributedVertex vertex = vertexMap.get(id);
            vertex.setName(vertexName);
            return vertex;
        }
        CustomAttributedVertex newVertex = new CustomAttributedVertex(id, vertexName);
        addVertex(newVertex);
        return newVertex;
    }

    @Override
    public CustomAttributedVertex addVertex() {
        CustomAttributedVertex vertex = super.addVertex();
        vertexMap.put(vertex.getId(), vertex);
        return vertex;
    }

    @Override
    public boolean addVertex(CustomAttributedVertex vertex) {
        if (super.addVertex(vertex)) {
            vertexMap.put(vertex.getId(), vertex);
            return true;
        }
        return false;
    }

    public boolean addVertex(AttributedVertex vertex) {
        CustomAttributedVertex cav = new CustomAttributedVertex(vertex.getId(), vertex.getName());
        if (super.addVertex(cav)) {
            vertexMap.put(cav.getId(), cav);
            return true;
        }
        return false;
    }

    public AttributedEdge addEdge(CustomAttributedVertex source, CustomAttributedVertex target, String edgeId) {
        AttributedEdge basicEdge = new AttributedEdge(edgeId);
        addEdge(source, target, basicEdge);
        return basicEdge;
    }

    @Override
    public boolean addEdge(CustomAttributedVertex source, CustomAttributedVertex target, AttributedEdge edge) {
        ensureInGraph(source);
        ensureInGraph(target);
        if (collapseDuplicateEdges) {
            AttributedEdge existingEdge = getEdge(source, target);
            if (existingEdge != null) {
                incrementWeightProperty(existingEdge);
                return true;
            }
        }
        return super.addEdge(source, target, edge);
    }

    @Override
    public AttributedEdge addEdge(CustomAttributedVertex source, CustomAttributedVertex target) {
        ensureInGraph(source);
        ensureInGraph(target);

        if (collapseDuplicateEdges) {
            AttributedEdge edge = getEdge(source, target);
            if (edge != null) {
                incrementWeightProperty(edge);
                return edge;
            }
        }
        return super.addEdge(source, target);
    }

    public int getEdgeCount() {
        return edgeSet().size();
    }

    public int getVertexCount() {
        return vertexSet().size();
    }

    public CustomAttributedVertex getVertex(String vertexId) {
        return vertexMap.get(vertexId);
    }

    private void ensureInGraph(CustomAttributedVertex vertex) {
        if (!containsVertex(vertex)) {
            addVertex(vertex);
        }
    }

    private static void incrementWeightProperty(AttributedEdge edge) {
        if (edge.hasAttribute(WEIGHT)) {
            String weightString = edge.getAttribute(WEIGHT);
            edge.setAttribute(WEIGHT, incrementWeightStringValue(weightString));
        } else {
            edge.setAttribute(WEIGHT, "2");
        }
    }

    private static String incrementWeightStringValue(String value) {
        int weight = Integer.parseInt(value);
        weight++;
        return Integer.toString(weight);
    }

    private static class VertexSupplier implements Supplier<CustomAttributedVertex> {
        long nextId = 1;

        @Override
        public CustomAttributedVertex get() {
            return new CustomAttributedVertex(Long.toString(nextId++));
        }
    }

    private static class EdgeSupplier implements Supplier<AttributedEdge> {
        long nextId = 1;

        @Override
        public AttributedEdge get() {
            return new AttributedEdge(Long.toString(nextId++));
        }
    }

}


class CustomAttributedVertex extends Attributed {

    public static final String NAME_KEY = "Name";
    public static final String VERTEX_TYPE_KEY = "VertexType";
    private final String id;

    private boolean visited;
    private boolean beingVisited;
    private List<CustomAttributedVertex> adjacencyList;


    public CustomAttributedVertex(String id, String name) {
        this.id = id;
        setName(name);

        this.visited = false;
        this.beingVisited = false;
        this.adjacencyList = new ArrayList<>();
    }

    public CustomAttributedVertex(String id) {
        this(id, id);

        this.visited = false;
        this.beingVisited = false;
        this.adjacencyList = new ArrayList<>();
    }


    public boolean isVisited() {
        return this.visited;
    }

    public void setVisited(boolean status) {
        this.visited = status;
    }

    public boolean isBeingVisited() {
        return this.beingVisited;
    }

    public void setBeingVisited(boolean status) {
        this.beingVisited = status;
    }

    public List<CustomAttributedVertex> getAdjacencyList() {
        return this.adjacencyList;
    }


    public void setName(String name) {
        setAttribute(NAME_KEY, name);
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return getAttribute(NAME_KEY);
    }

    @Override
    public String toString() {
        return getName() + " (" + id + ")";
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        AttributedVertex other = (AttributedVertex) obj;
        return id.equals(other.getId());
    }

    public String getVertexType() {
        return getAttribute(VERTEX_TYPE_KEY);
    }

    public void setVertexType(String vertexType) {
        setAttribute(VERTEX_TYPE_KEY, vertexType);
    }

    public void addNeighbor(CustomAttributedVertex adjacent) {
        this.adjacencyList.add(adjacent);
    }

}


class MemoryStructure {

    private final Address startAddress;

    private final AddressSet addressSet;

    private final long addressSetSize;

    public MemoryStructure(Address address, AddressSet addressSet) {
        this.startAddress = address;
        this.addressSet = addressSet;
        this.addressSetSize = addressSet.getNumAddresses();
    }

    public Address getStartAddress() {
        return this.startAddress;
    }

    public AddressSet getAddressSet() {
        return this.addressSet;
    }

    public long getAddressSetSize() {
        return this.addressSetSize;
    }

    public Address getLastAddress() {
        return this.addressSet.getMaxAddress();
    }

    public boolean contains(Address address) {
        return this.addressSet.contains(address);
    }

}
