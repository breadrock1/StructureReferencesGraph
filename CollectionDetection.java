import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Spliterator;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.EmptyGraphType;
import ghidra.service.graph.GraphDisplay;


public class CollectionDetection extends GhidraScript {

	private Program program;
	private PluginTool pluginTool;
	private FlatProgramAPI flatProgramAPI;
	private ReferenceManager referenceManager;
	
	private AttributedGraph graph;
	private Map<Address, AttributedVertex> graphNodes;


    @Override
    public void run() throws Exception {
    	this.program = currentProgram;
    	this.pluginTool = getState().getTool();
    	this.referenceManager = this.program.getReferenceManager();
    	this.flatProgramAPI = new FlatProgramAPI(this.program);
    	
		GraphDisplayBroker service = this.pluginTool.getService(GraphDisplayBroker.class);
		GraphDisplay display = service.getDefaultGraphDisplay(false, this.monitor);
		
		Map<Address, List<Reference>> dataReferences = findDataReferences();
		Map<Address, List<Address>> structureReferences = findStructureReferences(dataReferences);
		
		this.graph = new AttributedGraph("Pointer References Graph", new EmptyGraphType());
		//generatePointersGraph(dataReferences);
		generateStructureGraph(structureReferences);
		display.setGraph(this.graph, "Pointer References Graph", false, this.monitor);
    }

    
    private Map<Address, List<Reference>> findDataReferences() {
    	AddressIterator addressIterator = currentProgram.getMemory().getAddresses(true);
    	List<Address> memoryAddresses = StreamSupport
    			.stream(addressIterator.spliterator(), false)
    			.collect(Collectors.toList());
    	
    	Map<Address, List<Reference>> availableReferences = memoryAddresses.stream()
    			.collect(Collectors.toMap(addr -> addr, addr -> this.getAddressReferences(addr)))
    			.entrySet()
    			.stream()
    			.filter(entry -> !entry.getValue().isEmpty())
    			.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));	

    	return availableReferences;
    }
    
    private List<Reference> getAddressReferences(Address address) {
    	List<Reference> availableReferences = new ArrayList<>();
    	
    	// TODO: Add this filter parameter optionally!
    	//int refsCountTo = this.referenceManager.getReferenceCountTo(address);
    	//int refsCountFrom = this.referenceManager.getReferenceCountFrom(address);
    	//int refsCountCommon = refsCountTo + refsCountFrom;
    	//if (refsCountCommon < 2) {
    	//	return List.of();
    	//}
    	
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

	private void generatePointersGraph(Map<Address, List<Reference>> memoryReferences) {
		this.graphNodes = memoryReferences.keySet()
				.stream()
				.collect(Collectors.toMap(addr -> addr, addr -> vertex(addr)));
		
		for (Address currAddress : memoryReferences.keySet()) {
			for (Reference reference : memoryReferences.get(currAddress)) {	
				Address toAddress = reference.getToAddress();
				Address fromAddress = reference.getFromAddress();
				
				AttributedVertex toVertex = getStoredVertexFromGraph(toAddress);
				AttributedVertex fromVertex = getStoredVertexFromGraph(fromAddress);
				
				edge(fromVertex, toVertex);
			}
		}
	}
	
    
    private Map<Address, List<Address>> findStructureReferences(Map<Address, List<Reference>> allReferences) {
    	Map<Address, List<Address>> structureReferences = new HashMap<>();
    	
    	List<Address> strctAddrsArray = allReferences.keySet()
    			.stream()
    			.sorted()
    			.collect(Collectors.toList());
    	
    	Address prevAddress = strctAddrsArray.get(0);
    	for (int i = 1; i < strctAddrsArray.size(); ++i) {
    		Address currAddress = strctAddrsArray.get(i);
    		Long prevAddressOffset = prevAddress.getOffset();
    		Long currAddressOffset = currAddress.getOffset();
    		Long addrsDifference = currAddressOffset - prevAddressOffset;

    		System.out.printf("%s -> %s: %s\n", prevAddressOffset, currAddressOffset, addrsDifference);

    		if (addrsDifference < 16) {
    			structureReferences.put(currAddress, List.of(currAddress, prevAddress));
    		}
    		
    		prevAddress = currAddress;
    	}
    	
    	return structureReferences;
    }
    

	private void generateStructureGraph(Map<Address, List<Address>> structureReferences) {
		this.graphNodes = structureReferences.keySet()
				.stream()
				.collect(Collectors.toMap(addr -> addr, addr -> vertex(addr)));
		
		for (List<Address> addrsPair : structureReferences.values()) {
			Address toAddress = addrsPair.get(0);
			Address fromAddress = addrsPair.get(1);
			
			AttributedVertex toVertex = getStoredVertexFromGraph(toAddress);
			AttributedVertex fromVertex = getStoredVertexFromGraph(fromAddress);
			
			edge(fromVertex, toVertex);
		}
	}
	
	private void generateFullGraph(Map<Address, List<Address>> structureReferences, Map<Address, List<Reference>> memoryReferences) {
		//Stream.concat(structureReferences.keySet().stream(), memoryReferences.keySet().stream())
		//	.collect(Collectors.toMap(addr -> addr, addr -> vertex(addr)));
		
		Map<Address, AttributedVertex> strctVertex = new HashMap<>();
		for (Address strctAddress : structureReferences.keySet()) {
			List<Address> refs = structureReferences.get(strctAddress);
			AttributedVertex node = vertex(refs .get(0), refs.get(1));
			strctVertex.put(strctAddress, node);
		}
		
		for (Address strctAddress : structureReferences.keySet()) {
			
		}
	}

	
	private AttributedVertex vertex(Address first, Address second) {
		String vertexLabel = String.format(
				"0x%s -> 0x%s", 
				Long.toHexString(first.getOffset()), 
				Long.toHexString(second.getOffset())
		);

		return graph.addVertex(vertexLabel, vertexLabel);
	}
	
	private AttributedVertex vertex(Address address) {
		String vertexLabel = String.format(
				"Address: 0x%s\nAddress size: %s bits\nPointer size: %s bytes", 
				Long.toHexString(address.getOffset()), 
				address.getSize(), 
				address.getPointerSize());

		return graph.addVertex(vertexLabel, vertexLabel);
	}

	private AttributedEdge edge(AttributedVertex v1, AttributedVertex v2) {
		return graph.addEdge(v1, v2);
	}
	
    private AttributedVertex getStoredVertexFromGraph(Address address) {
    	if (!this.graphNodes.containsKey(address)) {
        	AttributedVertex attrVertex = vertex(address);
    		this.graphNodes.put(address, attrVertex);
    		return attrVertex;
    	}

		return this.graphNodes.get(address);
    }
    
    // ----------------------------------------------------------------------------------------
    // TODO: How detect structures? The first idea is comparing addresses subtraction
    // with optional parameter like {8, 16, 32} bytes and puts to mappa. 
    private void test(Map<Address, List<Reference>> memoryReferences) throws MemoryAccessException {
    	AddressFactory addressFactory = this.program.getAddressFactory();
		AddressIterator memoryIterator = this.program.getMemory().getAddresses(true);
		//Spliterator<Address> memorySpliterator = memoryIterator.spliterator();
		//Stream<Address> memoryStream = StreamSupport.stream(memorySpliterator, false);

		while (memoryIterator.hasNext() && !monitor.isCancelled()) {
			Address startBlockAddr = memoryIterator.next();
			String currHexAddress = Long.toHexString(startBlockAddr.getOffset());
			//Address endBlockAddr = addressFactory.getAddress(getCategory());
			Data dataAtAddr = flatProgramAPI.getDataAt(startBlockAddr);
			if (dataAtAddr == null) {
				continue;
			}
			
			ReferenceIterator refsToIter = dataAtAddr.getReferenceIteratorTo();
			String refsTo = StreamSupport.stream(refsToIter.spliterator(), false)
					.map(Reference::toString)
					.collect(Collectors.joining(", "));
			
			Reference[] refsFromArr = dataAtAddr.getReferencesFrom();
			String refsFrom = List.of(refsFromArr)
					.stream()
					.map(Reference::toString)
					.collect(Collectors.joining(", "));
			
			System.out.println("0x" + startBlockAddr + "\t->" + dataAtAddr.toString());
			System.out.println(refsTo + "\n" + refsFrom + "\n");
			//.getAddressSet(minAddr, maxAddr)
		}
		
		for (Address currAddress : memoryReferences.keySet()) {
			String currHexAddress = Long.toHexString(currAddress.getOffset());
			//AddressTable tableEntry = AddressTable.getEntry(
			//		this.program, currAddress, this.monitor, 
			//		true, -1, 1, 0, AddressTable.MINIMUM_SAFE_ADDRESS, true);
			//
			//AddressSetView addrSet = tableEntry.getTableBody();
			//Address start = tableEntry.getTopAddress();
			//int tableLen = tableEntry.getNumberAddressEntries();
			//Address addrs[] = tableEntry.getTableElements();
			
			Reference[] flowReferences = referenceManager.getFlowReferencesFrom(currAddress);
			Bookmark[] bookmarks = this.flatProgramAPI.getBookmarks(currAddress);
			
			byte[] octaAddrBytes = this.flatProgramAPI.getBytes(currAddress, 8);
			String octaAddrBytesHex = byteArrayToHex(octaAddrBytes);
			
			byte addrByte = this.flatProgramAPI.getByte(currAddress);
			if (addrByte == 0x0) {
				continue;
			}
			//System.out.println("0x" + currHexAddress + "\t\t->" + addrByte);
			//System.out.println("0x" + Long.toHexString(currAddress.getOffset()));
		}
    }
    
    private static String byteArrayToHex(byte[] a) {
	   StringBuilder sb = new StringBuilder(a.length * 2);
	   for(byte b: a) {
	      sb.append(String.format("%02x", b));
	   }
	   return sb.toString();
	}

}
