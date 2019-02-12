
def get_results(s_path,des_path,los,para):
    
    t_output = sys.stdout
    file = open(des_path,'w+')
    sys.stdout = file
    datas = read_data(s_path)
    t_funclus = split_byfc(datas,los)
    #print('split_start')
    #for t_key in t_funclus:
    #    print_clus(t_funclus[t_key],'p')
    #print('split_end')

    t_fdatas = sample_data(t_funclus,2000)
    t_fdatas = short_messages(t_fdatas,100)
    #get_lengths(t_fdatas)
    #print_clus(t_fdatas,'sample')
    #sys.exit()
    t_clus = clus_bynw(t_fdatas,para)
    t_fmes = []
    for t_clu in t_clus:
        t_messages = t_clu.messages
        t_M = []
        for t_me in t_messages:
            t_M.append(t_me.data)
        t_fmes.append(t_M)

        #print_clus(t_M,'nw')
    #print('start')
    get_precess(t_fmes,los,t_funclus.keys())
    #print('end')

    #t_tmes = clus_byfun(t_fdatas,los)
    #get_precess(t_tmes,los,t_funclus.keys())
