for i in $(ip netns | cut -d' ' -f 1);
    do      
    sudo ip netns exec $i ss -p | grep 10.1.2.5;
    echo $i;    
done 
