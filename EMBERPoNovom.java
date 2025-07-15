import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.lang3.StringEscapeUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import weka.core.Utils;

/*
spracovanie EMBER datasetu na vektorizaciu. (c) 2023 - 2025 Jan Mojzis, jan.mojzis@savba.sk
DOLEZITE: kod funguje pre dataset EMBER:
    Hyrum S. Anderson and Phil Roth. EMBER: An Open Dataset for Training Static PEMalware Machine Learning Models. ArXiv e-prints, 2018
a tam obzvlast, kod je nastaveny, aby uspesne parsoval spojene datasety: 
        train_features_0.jsonl + train_features_1.jsonl + train_features_2.jsonl + train_features_3.jsonl + train_features_4.jsonl + train_features_5.jsonl
je to dane tym, ze v kode je napevno dany pocet stlpcov = 386. Ked chces spracovat ine kombinacie EMBER datasetov, musis si zistit potrebny maximalny pocet atributov, ktore moze 1 json objekt mat,
to ti vypisuje aj tento kod, ktory pocas spracovania vypisuje pocet stlpcov

Kod vytvara medzireprezentaciu datasetu, robi sa tu vytahovanie akcii, sekcii, ich tried, atributov a flagov. Kazdy json objekt je tu uvedeny ako 1 riadok. Na zaciatku vystupu je zoznam max. poctu atributov pre 1 json objekt.
Ten bol stanoveny prave pre tuto kombinaciu EMBER datasetov.
Vystup, ktory sa tu generuje sluzi ako vstup pre tvorbu bag-of-words reprezentacie, co je finalna reprezentacia. Bag-of-words spravi napriklad Weka:
 weka.filters.unsupervised.attribute.StringToWordVector -c first -R last -M 5 -V -W 500000 -prune-rate -1.0 -N 0 -stemmer weka.core.stemmers.NullStemmer -stopwords-handler weka.core.stopwords.Null -tokenizer "weka.core.tokenizers.WordTokenizer -delimiters ?"

Po vykonani Bag-of-words je vytvorena velka matica o dimenzii x*y = 9607x600000, teda 9 607 atributov x 600 000 zaznamov (300x malware, 300k benigne)
Atribut triedy je prvy atribut. Odporuca sa dat si na tuto skutocnost pozor pri naslednej klasifikacii / supervised redukcii dimenzionality. Taktiez sa odporuca, pred trenovanim vykonat randomizaciu poradia zaznamov          
*/

public class EMBERPoNovom {
	/*
	private static HashSet<String> sectionPropsMem = new HashSet<String>(Arrays.asList(new String[] {
			"MEM_EXECUTE","MEM_WRITE","MEM_READ","MEM_SHARED"
			}));
	*/
	private  HashMap<String,String> sectionPropsMemMap = new HashMap<String,String>();
	private  HashSet<String> generalHasBinary = new HashSet<String>(Arrays.asList(new String[] {
			"has_resources","has_debug","exports","has_signature","has_tls","has_relocations","symbols"
	}));
	private  HashSet<String> sectionCNTveci = new HashSet<String>(Arrays.asList(new String[] {
		"CNT_CODE","CNT_INITIALIZED_DATA","CNT_UNINITIALIZED_DATA"	
	}));
	private HashMap<String,String> actions_mapping = new HashMap<String,String>();
	private int max_cols = 0;


	public EMBERPoNovom(String[] args) {
		try {

			sectionPropsMemMap.put("MEM_EXECUTE", "_executable");
			sectionPropsMemMap.put("MEM_WRITE", "_writable");
			sectionPropsMemMap.put("MEM_READ", "_readable");
			sectionPropsMemMap.put("MEM_SHARED", "_shareable");
			
			naplnActionsMapping(actions_mapping);
			
			HashMap<String,String> MAEC_imports = new HashMap<String,String>();
			HashSet<String> standard_section_names = new HashSet<String>();
			
			nacitajMapovanie(MAEC_imports,"d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\actions.json");
			nacitajStandardSekcie(standard_section_names,"d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\section_names.json");
			
			BufferedReader br = new BufferedReader(new FileReader(new File("d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\ember2018-0-5.json")),15000000);
			BufferedWriter bw = new BufferedWriter(new FileWriter(new File("d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\ember2018-0-5-svec_v2x.arff")),15000000);
			
			//BufferedReader br = new BufferedReader(new FileReader(new File("d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\pokus\\ember2018-1-5.json")),15000000);
			//BufferedWriter bw = new BufferedWriter(new FileWriter(new File("d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\pokus\\ember2018-1-5-svec_v2x.arff")),15000000);
			
			// peter anthony
			//BufferedReader br = new BufferedReader(new FileReader(new File("d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\peter anthony 5000 5000\\dataset_1_10000_raw.json")));
/*			
			BufferedReader br = new BufferedReader(new FileReader(new File("d:\\Jan\\_DATA\\EMBER 2018\\od sveca 1.zip\\dataset_1_10000_raw.json")));
			BufferedWriter bw = new BufferedWriter(new FileWriter(new File("d:\\Jan\\_DATA\\EMBER 2018\\od sveca 1.zip\\dataset_1_10000_raw.arff")));
			*/
			// pre kontrolu, kontrola ok., toto ide cernochovi
			/*
			BufferedReader br = new BufferedReader(new FileReader(new File("d:\\Jan\\_DATA\\EMBER 2018\\pre cernocha 1k a 10k\\kontrola\\dataset_1_10000_raw.json")));
			BufferedWriter bw = new BufferedWriter(new FileWriter(new File("d:\\Jan\\_DATA\\EMBER 2018\\pre cernocha 1k a 10k\\kontrola\\dataset_1_10000_raw.arff")));
			*/
			// 10k
			/*
			BufferedReader br = new BufferedReader(new FileReader(new File("d:\\Jan\\_DATA\\EMBER 2018\\pre cernocha 1k a 10k\\10k_1\\dataset_1_10000_raw.json")));
			BufferedWriter bw = new BufferedWriter(new FileWriter(new File("d:\\Jan\\_DATA\\EMBER 2018\\pre cernocha 1k a 10k\\10k_1\\dataset_1_10000_raw.arff")));
			*/
			// 1k
			/*
			BufferedReader br = new BufferedReader(new FileReader(new File("d:\\Jan\\_DATA\\EMBER 2018\\pre cernocha 1k a 10k\\1k_1\\dataset_1_1000_raw.json")));
			BufferedWriter bw = new BufferedWriter(new FileWriter(new File("d:\\Jan\\_DATA\\EMBER 2018\\pre cernocha 1k a 10k\\1k_1\\dataset_1_1000_raw.arff")));
			*/
			String line;
			JSONParser parser = new JSONParser();
			int limit = -1; //35000;//-1;//5500;
			//int limit = 1373; //35000;//-1;//5500;
			int zaznam=0;
			int tisic = 0;
			int zaznamov = 386;//385;//315;
			bw.write("@relation 'ember2018-train_feat-0-5_a_test_feat'\r\n\r\n");
			for (int i = 1; i <= zaznamov; i++)
				bw.write("@attribute str"+i+" string\r\n");
			bw.write("@attribute malware_benign {malware,benign}\r\n");
			bw.write("\r\n@data\r\n");
			String tmp;
			while ((line = br.readLine())!=null) {
				zaznam++;
				tisic++;
				//if (zaznam >= 32700-10+312 && zaznam <= 32700+10+312) continue;
				//if (zaznam >= 32700-10 && zaznam <= 32700+10) continue;
				//if (zaznam >= 32380 && zaznam <= 32100) continue;
				//if (zaznam == 32350+904-1) continue;
				if (tisic==1000) {
					tisic = 0;
					System.out.println(zaznam + " (max. cc: "+max_cols+")");
				}
				if (zaznam == limit) break;
				JSONObject obj = (JSONObject) parser.parse(line);
				ArrayList<String> atributy = zaznam(MAEC_imports,standard_section_names,obj);
				if (atributy == null) continue;
				//java.
				/*if (zaznam > 32381) {
					//System.out.println(line);
					for (int i = 0; i < atributy.size(); i++)
						System.out.println(atributy.get(i));
					break;
				}*/
				
				// az ked vieme kolko je features
				
				for (int i = 0; i < zaznamov; i++)
					if (i < atributy.size()-1) {
						tmp = atributy.get(i);
						//tmp = tmp.toLowerCase();
						//tmp = StringEscapeUtils.escapeJava(tmp);
						tmp = Utils.quote(tmp);
						bw.write(tmp+",");

					}
					else bw.write("?,");
				
				bw.write(atributy.get(atributy.size()-1)+"\r\n");
				
				
				
		//		System.out.println("------------------------------------------------------------------");
			}
			System.out.println("max cols count: "+max_cols);
			// max cols count = 312
			// a jeden cielovy
			
			

			br.close();
			bw.close();
		} catch (Exception e) {
			e.printStackTrace();
		}	}

	private void naplnActionsMapping(HashMap<String, String> actions_mapping2) {
		String value = "act_am_";//"access_management_";
		actions_mapping.put("add-user", value);
		actions_mapping.put("change-password", value);
		actions_mapping.put("delete-user", value);
		actions_mapping.put("enumerate-users", value);
		actions_mapping.put("get-username", value);
		actions_mapping.put("logon-as-user", value);
		actions_mapping.put("remove-user-from-group",value);
		
		value = "act_adbg_";//"_actions_anti_debug";
		actions_mapping.put("check-for-kernel-debugger", value);
		actions_mapping.put("check-for-remote-debugger", value);
		actions_mapping.put("output-debug-string", value);
		
		value = "act_acry_";//"_actions_cryptography";
		actions_mapping.put("encrypt", value);
		actions_mapping.put("decrypt", value);
		actions_mapping.put("generate-key", value);
		
		value = "act_adh_";//"_actions_directory_handling";
		actions_mapping.put("delete-directory", value);
		actions_mapping.put("monitor-directory", value);
		actions_mapping.put("open-directory", value);
		
		value = "act_adm_";//"_actions_disk_management";
		actions_mapping.put("enumerate-disks", value);
		actions_mapping.put("get-disk-attributes", value);
		actions_mapping.put("get-disk-type", value);
		actions_mapping.put("mount-disk", value);
		actions_mapping.put("unmount-disk", value);
		value = "act_afh_";//"_actions_file_handling";
		actions_mapping.put("close-file", value);
		actions_mapping.put("copy-file", value);
		actions_mapping.put("create-file", value);
		actions_mapping.put("create-file-mapping", value);
		actions_mapping.put("create-file-symbolic-link", value);
		actions_mapping.put("delete-file", value);
		actions_mapping.put("download-file", value);
		actions_mapping.put("execute-file", value);
		actions_mapping.put("find-file", value);
		actions_mapping.put("get-file-or-directory-attributes", value);
		actions_mapping.put("get-temporary-files-directory", value);
		actions_mapping.put("lock-file", value);
		actions_mapping.put("map-file-into-process", value);
		actions_mapping.put("move-file", value);
		actions_mapping.put("open-file-mapping", value);
		actions_mapping.put("read-from-file", value);
		actions_mapping.put("set-file-or-directory-attributes", value);
		actions_mapping.put("unlock-file", value);
		actions_mapping.put("unmap-file-from-process", value);
		actions_mapping.put("write-to-file", value);
		
		value = "act_ipc_";
		actions_mapping.put("connect-to-named-pipe", value);
		actions_mapping.put("create-mailslot", value);
		actions_mapping.put("create-named-pipe", value);
		
		value = "act_lh_";
		actions_mapping.put("enumerate-libraries", value);
		actions_mapping.put("free-library", value);
		actions_mapping.put("get-function-address", value);
		actions_mapping.put("load-library", value);
		
		value = "act_net_";
		actions_mapping.put("accept-socket-connection", value);
		actions_mapping.put("bind-address-to-socket", value);
		actions_mapping.put("close-socket", value);
		actions_mapping.put("connect-to-ftp-server", value);
		actions_mapping.put("connect-to-socket", value);
		actions_mapping.put("connect-to-url", value);
		actions_mapping.put("create-socket", value);
		actions_mapping.put("get-host-by-address", value);
		actions_mapping.put("get-host-by-name", value);
		actions_mapping.put("listen-on-socket", value);
		actions_mapping.put("send-data-on-socket", value);
		actions_mapping.put("send-dns-query", value);
		actions_mapping.put("send-http-connect-request", value);
		actions_mapping.put("send-icmp-request", value);
		
		value = "act_ph_";
		actions_mapping.put("allocate-process-virtual-memory", value);
		actions_mapping.put("create-process", value);
		actions_mapping.put("enumerate-processes", value);
		actions_mapping.put("flush-process-instruction-cache", value);
		actions_mapping.put("free-process-virtual-memory", value);
		actions_mapping.put("get-process-current-directory", value);
		actions_mapping.put("get-process-environment-variable", value);
		actions_mapping.put("get-process-startupinfo", value);
		actions_mapping.put("kill-process", value);
		actions_mapping.put("modify-process-virtual-memory-protection", value);
		actions_mapping.put("open-process", value);
		actions_mapping.put("read-from-process-memory", value);
		actions_mapping.put("set-process-current-directory", value);
		actions_mapping.put("set-process-environment-variable", value);
		actions_mapping.put("sleep-process", value);
		actions_mapping.put("write-to-process-memory", value);
		
		value = "act_rh_";
		actions_mapping.put("close-registry-key", value);
		actions_mapping.put("create-registry-key", value);
		actions_mapping.put("create-registry-key-value", value);
		actions_mapping.put("delete-registry-key-value", value);
		actions_mapping.put("delete-registry-key", value);
		actions_mapping.put("enumerate-registry-key-subkeys", value);
		actions_mapping.put("enumerate-registry-key-values", value);
		actions_mapping.put("modify-registry-key", value);
		actions_mapping.put("monitor-registry-key", value);
		actions_mapping.put("open-registry-key", value);
		actions_mapping.put("read-registry-key-value", value);
		
		value = "act_rs_";
		actions_mapping.put("add-network-share", value);
		actions_mapping.put("delete-network-share", value);
		actions_mapping.put("enumerate-network-shares", value);
		
		value = "act_sh_";
		actions_mapping.put("create-service", value);
		actions_mapping.put("delete-service", value);
		actions_mapping.put("enumerate-services", value);
		actions_mapping.put("modify-service-configuration", value);
		actions_mapping.put("open-service", value);
		actions_mapping.put("start-service", value);
		actions_mapping.put("stop-service", value);
		
		value = "act_sph_";
		actions_mapping.put("create-critical-section", value);
		actions_mapping.put("create-event", value);
		actions_mapping.put("create-mutex", value);
		actions_mapping.put("create-semaphore", value);
		actions_mapping.put("delete-critical-section", value);
		actions_mapping.put("open-event", value);
		actions_mapping.put("open-mutex", value);
		actions_mapping.put("open-semaphore", value);
		actions_mapping.put("release-critical-section", value);
		actions_mapping.put("release-mutex", value);
		actions_mapping.put("release-semaphore", value);
		actions_mapping.put("reset-event", value);
		
		value = "act_sm_";
		actions_mapping.put("add-scheduled-task", value);
		actions_mapping.put("get-elapsed-system-up-time", value);
		actions_mapping.put("get-netbios-name", value);
		actions_mapping.put("get-system-global-flags", value);
		actions_mapping.put("get-system-time", value);
		actions_mapping.put("get-windows-directory", value);
		actions_mapping.put("get-windows-system-directory", value);
		actions_mapping.put("set-netbios-name", value);
		actions_mapping.put("set-system-time", value);
		actions_mapping.put("shutdown-system", value);
		actions_mapping.put("unload-driver", value);
		
		value = "act_th_";
		actions_mapping.put("create-remote-thread-in-process", value);
		actions_mapping.put("create-thread", value);
		actions_mapping.put("enumerate-threads", value);
		actions_mapping.put("get-thread-context", value);
		actions_mapping.put("kill-thread", value);
		actions_mapping.put("queue-apc-in-thread", value);
		actions_mapping.put("revert-thread-to-self", value);
		actions_mapping.put("set-thread-context", value);
		
		value = "act_wh_";
		actions_mapping.put("add-windows-hook", value);
		actions_mapping.put("create-dialog-box", value);
		actions_mapping.put("create-window", value);
		actions_mapping.put("enumerate-windows", value);
		actions_mapping.put("find-window", value);
		actions_mapping.put("kill-window", value);
		actions_mapping.put("show-window", value);	
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		/*
		try {
		BufferedReader br = new BufferedReader(new FileReader(new File("d:\\Jan\\_DATA\\EMBER 2018\\cely train 2018\\ember2018-1-5-svec.arff")));
		String line;
		//int okolie = 32700+312;
		int okolie = 32700;
		int riadok = 0;
		while((line = br.readLine())!=null) {
			riadok++;
			
			if (riadok >= okolie-3 && riadok <= okolie+3) {
				//System.out.println(line);
				//System.out.println("---------------------------------------------");
				System.out.println(line.split(",").length);
			}
			if (riadok > okolie +4) break;
			
		}
		br.close();
		}catch(Exception e) {
			e.printStackTrace();
		}*/
		new EMBERPoNovom(args);
	}

	private  ArrayList<String> zaznam(HashMap<String, String> MAEC_imports, HashSet<String> standard_section_names,JSONObject obj) throws UnsupportedEncodingException {
		//StringBuilder sb = new StringBuilder(8192);
	//	boolean has_nonstandard_name = false;
		String malware_benign = "";
		/*
		HashSet<String> pouzite_funkcie = new HashSet<String>();
		HashSet<String> general_has_veci = new HashSet<String>();
		HashSet<String> sections_has_veci = new HashSet<String>();
		HashSet<String> strings_has_veci = new HashSet<String>();
		HashSet<String> header_veci = new HashSet<String>();
		HashSet<String> actions = new HashSet<String>();
		HashSet<String> datadirs = new HashSet<String>();
		*/
		HashSet<String> all_features = new HashSet<String>();
		String MAEC_mapovana_funkcia = "";
		boolean clr = false;
		boolean dirsize = false;
		boolean has_section_high_entropy = false;
		boolean has_nonstandard_section_name = false;
		
		//boolean has_behaviour = false;
		int executable_sections_count=0;
		boolean has_nonexexutable_section = false;
		boolean has_write_execute_section = false;
		int colscount = 0;
		for (Object o : obj.entrySet()) {
			if (o instanceof Map.Entry) {
				Object k = ((Map.Entry)o).getKey();
				Object v = ((Map.Entry)o).getValue();
				if (k.equals("imports")) {
					// prebehnut v a spracovat nazvy funkcii podla sveca
				//	System.out.println(v.getClass().getName());
					if (v instanceof JSONObject) {
						Set funkcie = ((JSONObject)v).entrySet();
						for (Object f : funkcie) {
							if (f instanceof Map.Entry) {
								Object k2 = ((Map.Entry)f).getKey();
								Object v2 = ((Map.Entry)f).getValue();
								//System.out.println(k2.getClass().getName() + " = "+v2.getClass().getName());
								//System.out.println(k2);
								if (v2 instanceof JSONArray) {
									JSONArray arr = (JSONArray)v2;
									for (Object funkcia : arr) {
										String str_funkcia = funkcia+"";
										str_funkcia = str_funkcia.toLowerCase();
										for (Entry<String,String> maecKV : MAEC_imports.entrySet()) {
											if (!actions_mapping.containsKey(maecKV.getValue())) continue;
											
											if (maecKV.getKey().contains(str_funkcia)) {
												String action_map = actions_mapping.get(maecKV.getValue());
												MAEC_mapovana_funkcia = maecKV.getValue();
												if (action_map != null)
												    all_features.add(action_map + MAEC_mapovana_funkcia);
												
											}
										}
										// hladame podla Sveca substring, ak je najdeny pridame, ale pokracujeme dalej
										// a ak najdeme znovu, vypiseme varovnu hlasku
										/*
										if (str_funkcia.startsWith("_"))
											str_funkcia = str_funkcia.substring(1);
										if (str_funkcia.endsWith("ExA")||str_funkcia.endsWith("ExW"))
											str_funkcia = str_funkcia.substring(0,str_funkcia.length()-3);
										else
										if (str_funkcia.endsWith("A")||str_funkcia.endsWith("W"))
											str_funkcia = str_funkcia.substring(0,str_funkcia.length()-1);
											
										str_funkcia = str_funkcia.toLowerCase();
										*/
										/*
										MAEC_mapovana_funkcia = "";
										if (MAEC_imports.containsKey(str_funkcia)) {
											MAEC_mapovana_funkcia = MAEC_imports.get(str_funkcia);
											all_features.add(MAEC_mapovana_funkcia);
										}

										String action_map = actions_mapping.get(MAEC_mapovana_funkcia);
										if (action_map != null)
										    all_features.add(action_map + MAEC_mapovana_funkcia);
										   */ 
									}
								}
							}
						}									
					}
				}
				else if (k.equals("section")) { // asi mame hotove
					for (Object o2 : ((JSONObject)v).entrySet()) {
						if (o2 instanceof Map.Entry) {
							Object k2 = ((Map.Entry)o2).getKey();
							Object v2 = ((Map.Entry)o2).getValue();
							//System.out.println(k2.getClass().getName() + " = " + v2.getClass().getName());
							if (v2 instanceof JSONArray) {
								for (Object oa : (JSONArray)v2) {
									if (oa instanceof JSONObject) {
										for (Object o3 : ((JSONObject)oa).entrySet()) {
											if (o3 instanceof Map.Entry) {
												Object k3 = ((Map.Entry)o3).getKey();
												Object v3 = ((Map.Entry)o3).getValue();
												//System.out.println(k3 + " = " + v3);
												String name = ((JSONObject)oa).get("name")+"";
												name = name.replace(">", "");
												name = name.replace("<", "");
												name = name.toLowerCase();
												name = name.replace(".", "");
												name = "sect_"+name;
												name = java.net.URLEncoder.encode(name, "UTF-8");
												all_features.add(name);
												if (k3.equals("name"))
													//if //System.out.println(v3);
													if (!standard_section_names.contains(v3.toString().toLowerCase())) {
													    all_features.add(name+ "_has_nonstandard_name");
													    has_nonstandard_section_name=true;
													}
														  //sections_has_veci.add(((JSONObject)oa).get("name")+ "_has_nonstandard_name");	
														// 
												if (k3.equals("entropy"))
													if (Double.parseDouble(v3.toString()) >= 7.0) {
													    all_features.add(name+ "_has_high_entropy");
													    has_section_high_entropy = true;
													}
														  //sections_has_veci.add(((JSONObject)oa).get("name")+ "_has_high_entropy");
												if (k3.equals("props"))
													if (v3 instanceof JSONArray) {
														for (Object o4 : (JSONArray) v3) {
															if (sectionPropsMemMap.containsKey(o4))
															    all_features.add(name+sectionPropsMemMap.get(o4));
																//sections_has_veci.add(((JSONObject)oa).get("name")+sectionPropsMemMap.get(o4));
															else if (sectionCNTveci.contains(o4))
															    all_features.add(name+"_has_"+o4);
																//sections_has_veci.add(((JSONObject)oa).get("name")+"_has_"+o4);
														}
														if (!((JSONArray) v3).contains("MEM_EXECUTE")) 
															has_nonexexutable_section = true;
														else if (((JSONArray) v3).contains("MEM_EXECUTE")) {
																if	(((JSONArray) v3).contains("MEM_WRITE")) { 
																	all_features.add(name+"_write_execute_section");
																	has_write_execute_section = true;
																}
																executable_sections_count++;
														}
															   //sections_has_veci.add(((JSONObject)oa).get("name")+"_write_execute_section");
															
														
															//sections_has_veci.add( ((JSONObject)oa).get("name")+"_nonexecutable_entry_point");
														//else executable_sections_count++;
													}
													
											}
											
										}
									}
								}
								
							}
						}
					}
				}
				else
					if (k.equals("general")) { // toto uz asi mame
						if (v instanceof JSONObject) {
							for (Object o2 : ((JSONObject)v).entrySet()) {
								//System.out.println(o2);
								if (o2 instanceof Map.Entry) {
									String k2 = ((Map.Entry)o2).getKey().toString();
									Object v2 = ((Map.Entry)o2).getValue();
									//System.out.println(k2 + " = "+v2);
									if (k2.equals("imports") && Integer.parseInt(v2.toString()) < 10)
									    all_features.add("has_nonstandard_imports_count");
										//general_has_veci.add("has_nonstandard_imports_count");
									else if (generalHasBinary.contains(k2)) {
										if (!v2.toString().equals("0"))
											if (k2.toString().startsWith("has_")) {
											    all_features.add(k2.toString());
												//general_has_veci.add(k2.toString());
											}else {
											    all_features.add("has_"+k2.toString());
												//general_has_veci.add("has_"+k2.toString());												
											}
										
									}
										/*
									if (k2.equals("has_resources") && !v2.equals("0"))
										general_has_veci.add("has_resources");
									else
									if (k2.equals("has_debug") && !v2.equals("0"))
										general_has_veci.add("has_debug");
									else
									if (k2.equals("exports") && !v2.equals("0"))
										general_has_veci.add("has_exports");
									else
									if (k2.equals("has_signature") && !v2.equals("0"))
										general_has_veci.add("has_signature");
									else
									if (k2.equals("has_tls") && !v2.equals("0"))
										general_has_veci.add("has_tls");
									else
									if (k2.equals("has_relocations") && !v2.equals("0"))
										general_has_veci.add("has_relocations");
									else
									if (k2.equals("symbols") && !v2.equals("0"))
										general_has_veci.add("has_symbols");
										*/
									/*else
									if (k2.equals("symbols") && Integer.parseInt(v2.toString()) > 0 )
										general_has_veci.add("has_symbols");
									*/
								}
								
							}
						}
					}else if (k.equals("strings")) {
						if (v instanceof JSONObject) {
							for (Object o2 : ((JSONObject)v).entrySet()) {
								if (o2 instanceof Map.Entry) {
									
									String k2 = ((Map.Entry)o2).getKey().toString();
									Object v2 = ((Map.Entry)o2).getValue();
									// entropia jednotlivych sekcii, nie tato zo strings
								/*	if (k2.equals("entropy") && Double.parseDouble(v2.toString()) >= 7)
										strings_has_veci.add("has_high_entropy");
									else*/
									if (k2.equals("registry") && !v2.toString().equals("0"))
										//strings_has_veci.add("has_registry_strings");
									    all_features.add("has_registry_strings");
										
									else
									if (k2.equals("urls") && !v2.toString().equals("0"))
									    all_features.add("has_urls_strings");
										//strings_has_veci.add("has_urls_strings");
									else
									if (k2.equals("paths") && !v2.toString().equals("0"))
									    all_features.add("has_paths_strings");
										//strings_has_veci.add("has_paths_strings");
									
									if (k2.equals("MZ") && !v2.toString().equals("1"))
									    all_features.add("has_nonstandard_mz");
										//strings_has_veci.add("has_nonstandard_mz");
								}
							}
						}
					}else if (k.equals("header")) { 
						if (v instanceof JSONObject) {
							for (Object o2 : ((JSONObject)v).entrySet()) {
								if (o2 instanceof Map.Entry) {
									Object k2 = ((Map.Entry)o2).getKey();
									Object v2 = ((Map.Entry)o2).getValue();
									//System.out.println(k2 + " = " +v2);		
									//System.out.println(o2.getClass().getName());
									//System.out.println(k2.getClass().getName() + " = " +v2.getClass().getName());
									if (v2 instanceof JSONObject) {
										for (Object o3 : ((JSONObject)v2).entrySet()) {
											//System.out.println(o3);
											if (o3 instanceof Map.Entry) {
												Object k3 = ((Map.Entry)o3).getKey();
												Object v3 = ((Map.Entry)o3).getValue();
												if (k3.equals("characteristics")) {
													if (v3 instanceof JSONArray) {
														for (Object o4 : (JSONArray)v3) {
															if (o4.equals("DLL"))
															    all_features.add("is_dll");
																//header_veci.add("is_dll");
														}
													}
												}
													//System.out.println(v3);
											}
										}
									}
								}
							}
									
						}
					} else if (k.equals("datadirectories")) {
						//System.out.println(v.getClass().getName());
						//System.out.println(v);
						
						if (v instanceof JSONArray)
							for (Object o2 : (JSONArray)v) 
								//System.out.println(o2.getClass().getName());
								//System.out.println(o2);
								if (o2 instanceof JSONObject) {									 
									Set datadirectories = ((JSONObject)o2).entrySet();
									//String dirname = "";
									clr = false;
									dirsize = false;
									for (Object o3 : datadirectories)
									{
										Object k2 = ((Map.Entry)o3).getKey();
										Object v2 = ((Map.Entry)o3).getValue();
										if (k2.equals("name") && v2.equals("CLR_RUNTIME_HEADER")) { 
											clr = true;
										//	dirname = v2.toString();
										}
										else if (k2.equals("size") && !v2.toString().equals("0"))
												dirsize=true;
										//  if (datadirectories.get)
									}
									if (clr && dirsize)
										//datadirs.add("clr_"+dirname);
										//datadirs.add("has_clr");
									    all_features.add("has_clr");
										
										
							}
					}
				/*
					else if (k.equals("sha256") && v.equals("6aa5a84686b959af64767d17b1e4d5ad59414a10b9039fb2deae666d984e48a4")) {
						//all_features.clear();
						//continue;
						System.out.println("tu");
					}*/
						//System.out.println("tu");
				//if (!k.equals("histogram") && !k.equals("sha265")&& !k.equals("md5")) {
				//	String vv = v.toString();
				if (k.equals("label")) {          // jeden atr. posledny je cielovy
					//System.out.println(v);
					if (v.toString().equals("0"))
							malware_benign="benign";
					else if (v.toString().equals("1"))
							malware_benign="malware";
					else {
						// vyclearuj
						/*
						header_veci.clear();
						strings_has_veci.clear();
						general_has_veci.clear();
						sections_has_veci.clear();
						pouzite_funkcie.clear();
						actions.clear();
						datadirs.clear();
						*/
						all_features.clear();
						return null;
					}
						
				}
					/*vv = vv.replace("[","[\r\n    ");
					vv = vv.replace("{","{\r\n  ");
					vv = vv.replace("]","\r\n]\r\n");
					vv = vv.replace("}","\r\n}\r\n");
					*/
					//System.out.println(k + " = " +vv);
			//	}
				// entropiu kazdej sekcie, 


				
			}
			//Node n = (Node)o;
			//System.out.println(o.getClass().getName());
		}
		if (executable_sections_count  > 1)
			//sections_has_veci.add("multiple_executable_sections");
			all_features.add("has_multiple_executable_sections"); // ok
		if (has_nonexexutable_section)
			//sections_has_veci.add("nonexecutable_entry_point");
			all_features.add("has_nonexecutable_entry_point");
		if (has_nonstandard_section_name)
			all_features.add("has_nonstandard_section_name");
		if (has_section_high_entropy)
			all_features.add("has_section_high_entropy");
		if (has_write_execute_section)
			all_features.add("has_write_execute_section");
			
		colscount = all_features.size();/*header_veci.size() + strings_has_veci.size() + general_has_veci.size() + sections_has_veci.size()+
				pouzite_funkcie.size() + actions.size() + datadirs.size();*/
		
		if (colscount >  max_cols)
			 max_cols = colscount;
		/*
		header_veci.clear();
		strings_has_veci.clear();
		general_has_veci.clear();
		sections_has_veci.clear();
		pouzite_funkcie.clear();
		actions.clear();
		datadirs.clear();
		*/
		//all_features.clear();
		ArrayList<String> list = new ArrayList<String>(all_features);
		list.add(malware_benign);
		return list;// sb.toString();
		}

	private  void nacitajStandardSekcie(HashSet<String> standard_section_names, String file) throws IOException, ParseException {
		BufferedReader br = new BufferedReader(new FileReader(new File(file)));
		JSONParser parser = new JSONParser();
		JSONObject obj = (JSONObject) parser.parse(br);
		for (Object o : obj.entrySet()) {
			//System.out.println(o.getClass().getName());
			if (o instanceof Map.Entry) {
				Object k = ((Map.Entry)o).getKey();
				Object v = ((Map.Entry)o).getValue();
				if (v instanceof JSONArray) {
					for (Object o2 : (JSONArray)v) {
						standard_section_names.add(o2+"");
					}
				}
				
			}
		}
		br.close();
		
	}

	private void nacitajMapovanie(HashMap<String, String> MAEC, String file) throws IOException, ParseException {
		BufferedReader br = new BufferedReader(new FileReader(new File(file)));
		JSONParser parser = new JSONParser();
		JSONObject obj = (JSONObject) parser.parse(br);
	    for (Object o : obj.entrySet()) {
	    	//System.out.println(o);
	    	if (o instanceof Map.Entry) {
	    		Object k = ((Map.Entry)o).getKey();
	    		Object v = ((Map.Entry)o).getValue();
	    		//System.out.print(k+"\n   ");
	    		if (v instanceof JSONArray) {
	    			JSONArray arr = (JSONArray)v;
	    			for (Object oa : arr) {
	    				//System.out.print(oa + ", ");
	    				MAEC.put(oa+"", k+"");
	    			//	System.out.println(oa);
	    			}
	    		}
	    		//System.out.println();
	    		//if (v instanceof HashSet)
	    	}
	    }
		br.close();
		
	}

}
